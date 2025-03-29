package dead.owner.deobf.transformers;

import dead.owner.deobf.Run;
import dead.owner.deobf.utils.wrapper.ClassWrapper;
import dead.owner.deobf.utils.wrapper.MethodWrapper;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.util.*;

/**
 * Transformer to remove useless code inserted for obfuscation
 */
public class UselessCodeRemover implements Transformer, Opcodes {
    
    private static final String[] USELESS_FIELD_PATTERNS = {
        "nothing_to_see_here", 
        "[A-Z][0-9a-zA-Z]{8,}", // Random capital-letter-starting fields
        "[a-z][0-9a-zA-Z]{8,}"  // Random lowercase-starting fields
    };
    
    private static final String[] USELESS_METHOD_PATTERNS = {
        "ssnqylnonlabsxrs",
        "wxmruihzjtkqxwmt", 
        "yrygjztjpoaufpwg",
        "ldnjatyadlrcgmta",
        "pyeyrrglswhnwgns",
        "[a-z]{10,}"          // Random method names
    };
    
    @Override
    public void transform(ClassWrapper classWrapper) {
        int removedFields = 0;
        int removedMethods = 0;
        
        // Remove useless static fields
        removedFields += removeUselessFields(classWrapper);
        
        // Remove useless methods
        removedMethods += removeUselessMethods(classWrapper);
        
        // Clean up methods with useless code
        int cleanedMethods = cleanupMethodBodies(classWrapper);
        
        if (removedFields > 0 || removedMethods > 0 || cleanedMethods > 0) {
            Run.log(classWrapper.getName() + " | Removed " + removedFields + " useless fields, " + 
                   removedMethods + " useless methods, and cleaned up " + cleanedMethods + " methods");
        }
    }
    
    /**
     * Remove useless fields from the class
     */
    private int removeUselessFields(ClassWrapper classWrapper) {
        List<FieldNode> fieldsToRemove = new ArrayList<>();
        
        for (FieldNode fieldNode : classWrapper.getFieldsAsNodes()) {
            if (isUselessField(fieldNode)) {
                fieldsToRemove.add(fieldNode);
            }
        }
        
        for (FieldNode fieldNode : fieldsToRemove) {
            classWrapper.getFieldsAsNodes().remove(fieldNode);
        }
        
        return fieldsToRemove.size();
    }
    
    /**
     * Check if a field is useless (just for obfuscation)
     */
    private boolean isUselessField(FieldNode fieldNode) {
        // Check field name against known patterns
        for (String pattern : USELESS_FIELD_PATTERNS) {
            if (fieldNode.name.matches(pattern)) {
                return true;
            }
        }
        
        // Check for ASCII art static arrays
        if (fieldNode.name.equals("nothing_to_see_here") || 
            (fieldNode.desc.equals("[Ljava/lang/String;") && 
             (fieldNode.access & ACC_STATIC) != 0)) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Remove useless methods from the class
     */
    private int removeUselessMethods(ClassWrapper classWrapper) {
        List<MethodNode> methodsToRemove = new ArrayList<>();
        
        for (MethodNode methodNode : classWrapper.getMethodsAsNodes()) {
            if (isUselessMethod(methodNode)) {
                methodsToRemove.add(methodNode);
            }
        }
        
        for (MethodNode methodNode : methodsToRemove) {
            classWrapper.getMethodsAsNodes().remove(methodNode);
        }
        
        return methodsToRemove.size();
    }
    
    /**
     * Check if a method is useless (just for obfuscation)
     */
    private boolean isUselessMethod(MethodNode methodNode) {
        // Check method name against known patterns
        for (String pattern : USELESS_METHOD_PATTERNS) {
            if (methodNode.name.matches(pattern)) {
                return true;
            }
        }
        
        // Check for byte array generator methods
        if (methodNode.desc.equals("()[B") && 
            methodNode.name.length() > 8 && 
            methodNode.name.matches("[a-z]+")) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Clean up method bodies by removing useless code
     */
    private int cleanupMethodBodies(ClassWrapper classWrapper) {
        int cleanedMethods = 0;
        
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            boolean cleaned = false;
            
            // Clean up var initialization with hash operations
            cleaned |= cleanupVarInitialization(methodWrapper);
            
            // Clean up switch statements with constants
            cleaned |= cleanupConstantSwitches(methodWrapper);
            
            // Clean up while(true) with unreachable code
            cleaned |= cleanupUnreachableWhileLoops(methodWrapper);
            
            // Remove useless variable XOR operations
            cleaned |= removeUselessXorOperations(methodWrapper);
            
            // Remove dead code after unconditional jumps or returns
            cleaned |= removeDeadCode(methodWrapper);
            
            if (cleaned) {
                cleanedMethods++;
            }
        }
        
        return cleanedMethods;
    }
    
    /**
     * Clean up variable initialization with hash operations
     */
    private boolean cleanupVarInitialization(MethodWrapper methodWrapper) {
        MethodNode methodNode = methodWrapper.getMethodNode();
        boolean modified = false;
        
        // Look for patterns like:
        // int var8 = 1784610355 ^ 659658962;
        
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Store next before potential modification
            
            if (insn instanceof LdcInsnNode && ((LdcInsnNode) insn).cst instanceof Integer) {
                AbstractInsnNode nextInsn = getNextRealInsn(insn);
                
                if (nextInsn instanceof LdcInsnNode && ((LdcInsnNode) nextInsn).cst instanceof Integer) {
                    AbstractInsnNode xorInsn = getNextRealInsn(nextInsn);
                    
                    if (xorInsn != null && xorInsn.getOpcode() == IXOR) {
                        AbstractInsnNode storeInsn = getNextRealInsn(xorInsn);
                        
                        if (storeInsn != null && storeInsn.getOpcode() >= ISTORE && storeInsn.getOpcode() <= ASTORE) {
                            // This is a pattern we want to clean up
                            int value1 = (Integer) ((LdcInsnNode) insn).cst;
                            int value2 = (Integer) ((LdcInsnNode) nextInsn).cst;
                            int result = value1 ^ value2;
                            
                            // Replace with direct load of the result
                            LdcInsnNode newInsn = new LdcInsnNode(result);
                            methodNode.instructions.insertBefore(insn, newInsn);
                            
                            // Remove the old instructions
                            methodNode.instructions.remove(insn);
                            methodNode.instructions.remove(nextInsn);
                            methodNode.instructions.remove(xorInsn);
                            
                            modified = true;
                            
                            // Next instruction is now after the inserted LDC
                            next = newInsn.getNext();
                        }
                    }
                }
            } else if (insn instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                
                // Look for useless XOR method calls
                if (methodInsn.name.matches("ssnqylnonlabsxrs|wxmruihzjtkqxwmt|yrygjztjpoaufpwg|ldnjatyadlrcgmta|pyeyrrglswhnwgns")) {
                    AbstractInsnNode prev1 = getPreviousRealInsn(insn);
                    AbstractInsnNode prev2 = prev1 != null ? getPreviousRealInsn(prev1) : null;
                    
                    // These are typically parameterized XOR operations
                    if (prev1 != null && prev2 != null && 
                        isPushingIntValue(prev1) && isPushingIntValue(prev2)) {
                        
                        int value1 = getIntValue(prev2);
                        int value2 = getIntValue(prev1);
                        int result = value1 ^ value2;
                        
                        // Replace with direct load of the result
                        LdcInsnNode newInsn = new LdcInsnNode(result);
                        methodNode.instructions.insertBefore(prev2, newInsn);
                        
                        // Remove the old instructions
                        methodNode.instructions.remove(prev2);
                        methodNode.instructions.remove(prev1);
                        methodNode.instructions.remove(insn);
                        
                        modified = true;
                        
                        // Next instruction is now after the inserted LDC
                        next = newInsn.getNext();
                    }
                }
            }
            
            insn = next;
        }
        
        return modified;
    }
    
    /**
     * Clean up switch statements with constants
     */
    private boolean cleanupConstantSwitches(MethodWrapper methodWrapper) {
        MethodNode methodNode = methodWrapper.getMethodNode();
        boolean modified = false;
        
        // Look for constant switch patterns, often in constructors or clinit methods
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Store next before potential modification
            
            if (insn instanceof TableSwitchInsnNode || insn instanceof LookupSwitchInsnNode) {
                // Check if the switch is based on a constant
                AbstractInsnNode prev = getPreviousRealInsn(insn);
                
                if (prev != null && isPushingIntValue(prev)) {
                    int switchValue = getIntValue(prev);
                    LabelNode targetLabel = null;
                    
                    // Determine which label to jump to
                    if (insn instanceof TableSwitchInsnNode) {
                        TableSwitchInsnNode tableSwitch = (TableSwitchInsnNode) insn;
                        
                        if (switchValue >= tableSwitch.min && switchValue <= tableSwitch.max) {
                            int index = switchValue - tableSwitch.min;
                            targetLabel = tableSwitch.labels.get(index);
                        } else {
                            targetLabel = tableSwitch.dflt;
                        }
                    } else if (insn instanceof LookupSwitchInsnNode) {
                        LookupSwitchInsnNode lookupSwitch = (LookupSwitchInsnNode) insn;
                        
                        int labelIndex = lookupSwitch.keys.indexOf(switchValue);
                        if (labelIndex >= 0) {
                            targetLabel = lookupSwitch.labels.get(labelIndex);
                        } else {
                            targetLabel = lookupSwitch.dflt;
                        }
                    }
                    
                    if (targetLabel != null) {
                        // Replace with a direct jump
                        JumpInsnNode gotoInsn = new JumpInsnNode(GOTO, targetLabel);
                        methodNode.instructions.insertBefore(prev, gotoInsn);
                        
                        // Remove the switch and its index
                        methodNode.instructions.remove(prev);
                        methodNode.instructions.remove(insn);
                        
                        modified = true;
                        
                        // Next instruction is now after the inserted GOTO
                        next = gotoInsn.getNext();
                    }
                }
            }
            
            insn = next;
        }
        
        return modified;
    }
    
    /**
     * Clean up unreachable while loops
     */
    private boolean cleanupUnreachableWhileLoops(MethodWrapper methodWrapper) {
        MethodNode methodNode = methodWrapper.getMethodNode();
        boolean modified = false;
        
        // Look for while(true) patterns with unreachable code
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Store next before potential modification
            
            // Check for while(true) { switch(...) { ... } }
            if (insn instanceof LabelNode) {
                AbstractInsnNode switchInsn = findNextSwitch(insn);
                
                if (switchInsn != null) {
                    AbstractInsnNode gotoInsn = findGotoToLabel(methodNode, (LabelNode) insn, switchInsn);
                    
                    if (gotoInsn != null) {
                        // This is a while(true) loop - check if it can be simplified
                        if (isConstantSwitch(switchInsn)) {
                            // The switch is based on a constant, so the loop can be simplified
                            // For now, we'll keep the switch but remove the outer loop
                            methodNode.instructions.remove(gotoInsn);
                            modified = true;
                        }
                    }
                }
            }
            
            insn = next;
        }
        
        return modified;
    }
    
    /**
     * Remove useless XOR operations
     */
    private boolean removeUselessXorOperations(MethodWrapper methodWrapper) {
        MethodNode methodNode = methodWrapper.getMethodNode();
        boolean modified = false;
        
        // Look for patterns like var8 = var8 ^ someValue;
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Store next before potential modification
            
            if (insn instanceof VarInsnNode && insn.getOpcode() >= ILOAD && insn.getOpcode() <= ALOAD) {
                int varIndex = ((VarInsnNode) insn).var;
                
                // Check if this is followed by a push, XOR, and store to the same variable
                AbstractInsnNode pushInsn = getNextRealInsn(insn);
                if (pushInsn != null && isPushingIntValue(pushInsn)) {
                    AbstractInsnNode xorInsn = getNextRealInsn(pushInsn);
                    
                    if (xorInsn != null && xorInsn.getOpcode() == IXOR) {
                        AbstractInsnNode storeInsn = getNextRealInsn(xorInsn);
                        
                        if (storeInsn instanceof VarInsnNode && 
                            storeInsn.getOpcode() == ISTORE && 
                            ((VarInsnNode) storeInsn).var == varIndex) {
                            
                            // This is a useless XOR operation - replace it with a direct value store
                            int value = getIntValue(pushInsn);
                            
                            // In this case, we can just remove all the instructions
                            // and replace with a single constant load and store
                            LdcInsnNode newLoadInsn = new LdcInsnNode(value);
                            VarInsnNode newStoreInsn = new VarInsnNode(ISTORE, varIndex);
                            
                            methodNode.instructions.insertBefore(insn, newLoadInsn);
                            methodNode.instructions.insertBefore(insn, newStoreInsn);
                            
                            // Remove all the old instructions
                            methodNode.instructions.remove(insn);
                            methodNode.instructions.remove(pushInsn);
                            methodNode.instructions.remove(xorInsn);
                            methodNode.instructions.remove(storeInsn);
                            
                            modified = true;
                            
                            // Next instruction is now after the inserted store
                            next = newStoreInsn.getNext();
                        }
                    }
                }
            }
            
            insn = next;
        }
        
        return modified;
    }
    
    /**
     * Remove dead code after unconditional jumps or returns
     */
    private boolean removeDeadCode(MethodWrapper methodWrapper) {
        MethodNode methodNode = methodWrapper.getMethodNode();
        boolean modified = false;
        
        // Start with a map of all labels that are jumped to
        Set<LabelNode> jumpTargets = new HashSet<>();
        
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof JumpInsnNode) {
                jumpTargets.add(((JumpInsnNode) insn).label);
            } else if (insn instanceof TableSwitchInsnNode) {
                TableSwitchInsnNode tableSwitchNode = (TableSwitchInsnNode) insn;
                jumpTargets.add(tableSwitchNode.dflt);
                jumpTargets.addAll(tableSwitchNode.labels);
            } else if (insn instanceof LookupSwitchInsnNode) {
                LookupSwitchInsnNode lookupSwitchNode = (LookupSwitchInsnNode) insn;
                jumpTargets.add(lookupSwitchNode.dflt);
                jumpTargets.addAll(lookupSwitchNode.labels);
            }
        }
        
        // Also consider try-catch blocks as jump targets
        if (methodNode.tryCatchBlocks != null) {
            for (TryCatchBlockNode tryCatchBlock : methodNode.tryCatchBlocks) {
                jumpTargets.add(tryCatchBlock.start);
                jumpTargets.add(tryCatchBlock.end);
                jumpTargets.add(tryCatchBlock.handler);
            }
        }
        
        // Now look for dead code
        AbstractInsnNode insn = methodNode.instructions.getFirst();
        while (insn != null) {
            AbstractInsnNode next = insn.getNext();
            
            if (insn.getOpcode() == GOTO || 
                (insn.getOpcode() >= IRETURN && insn.getOpcode() <= RETURN) || 
                insn.getOpcode() == ATHROW) {
                
                // This is an unconditional flow control - the next instructions are dead until a jump target
                AbstractInsnNode current = next;
                while (current != null && 
                      !(current instanceof LabelNode && jumpTargets.contains(current))) {
                    AbstractInsnNode toRemove = current;
                    current = current.getNext();
                    
                    // Only remove non-label, non-line number, and non-frame nodes
                    if (!(toRemove instanceof LabelNode) && 
                        !(toRemove instanceof LineNumberNode) && 
                        !(toRemove instanceof FrameNode)) {
                        methodNode.instructions.remove(toRemove);
                        modified = true;
                    }
                }
                
                // Skip to the next label
                next = current;
            }
            
            insn = next;
        }
        
        return modified;
    }
    
    /**
     * Find the next switch instruction
     */
    private AbstractInsnNode findNextSwitch(AbstractInsnNode start) {
        AbstractInsnNode current = start.getNext();
        
        // Look for TABLESWITCH or LOOKUPSWITCH within a reasonable distance
        int distance = 0;
        while (current != null && distance < 10) {
            if (current instanceof TableSwitchInsnNode || current instanceof LookupSwitchInsnNode) {
                return current;
            }
            
            current = current.getNext();
            distance++;
        }
        
        return null;
    }
    
    /**
     * Find a GOTO instruction that jumps to a given label
     */
    private AbstractInsnNode findGotoToLabel(MethodNode methodNode, LabelNode target, AbstractInsnNode searchEnd) {
        AbstractInsnNode current = searchEnd;
        
        // Search forward for a GOTO to the target
        while (current != null) {
            if (current instanceof JumpInsnNode && current.getOpcode() == GOTO) {
                JumpInsnNode gotoInsn = (JumpInsnNode) current;
                if (gotoInsn.label == target) {
                    return current;
                }
            }
            
            current = current.getNext();
        }
        
        return null;
    }
    
    /**
     * Check if a switch instruction's condition is a constant
     */
    private boolean isConstantSwitch(AbstractInsnNode switchInsn) {
        AbstractInsnNode prev = getPreviousRealInsn(switchInsn);
        return prev != null && isPushingIntValue(prev);
    }
    
    /**
     * Check if an instruction is pushing an integer value
     */
    private boolean isPushingIntValue(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        return (opcode >= ICONST_M1 && opcode <= ICONST_5) ||
               opcode == BIPUSH || 
               opcode == SIPUSH || 
               (insn instanceof LdcInsnNode && ((LdcInsnNode) insn).cst instanceof Integer);
    }
    
    /**
     * Get the integer value being pushed
     */
    private int getIntValue(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        
        if (opcode >= ICONST_M1 && opcode <= ICONST_5) {
            return opcode - ICONST_0;
        } else if (opcode == BIPUSH || opcode == SIPUSH) {
            return ((IntInsnNode) insn).operand;
        } else if (insn instanceof LdcInsnNode && ((LdcInsnNode) insn).cst instanceof Integer) {
            return (Integer) ((LdcInsnNode) insn).cst;
        }
        
        return 0; // Default
    }
    
    /**
     * Get the next significant instruction
     */
    private AbstractInsnNode getNextRealInsn(AbstractInsnNode insn) {
        AbstractInsnNode current = insn.getNext();
        while (current != null && (current instanceof LabelNode || 
                                  current instanceof LineNumberNode || 
                                  current instanceof FrameNode)) {
            current = current.getNext();
        }
        return current;
    }
    
    /**
     * Get the previous significant instruction
     */
    private AbstractInsnNode getPreviousRealInsn(AbstractInsnNode insn) {
        AbstractInsnNode current = insn.getPrevious();
        while (current != null && (current instanceof LabelNode || 
                                  current instanceof LineNumberNode || 
                                  current instanceof FrameNode)) {
            current = current.getPrevious();
        }
        return current;
    }
}