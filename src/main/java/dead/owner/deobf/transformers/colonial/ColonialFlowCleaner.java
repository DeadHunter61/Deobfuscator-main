package dead.owner.deobf.transformers.colonial;

import dead.owner.deobf.Run;
import dead.owner.deobf.utils.wrapper.ClassWrapper;
import dead.owner.deobf.utils.wrapper.MethodWrapper;
import dead.owner.deobf.transformers.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.util.*;

/**
 * Transformer to clean flow obfuscation techniques specific to Colonial Obfuscator.
 * Colonial adds various control flow obfuscations like:
 * - Extra jumps and unnecessary branches
 * - Dead code blocks
 * - Fake conditional checks
 * - Loop obfuscation
 */
public class ColonialFlowCleaner implements Transformer, Opcodes {
    
    @Override
    public void transform(ClassWrapper classWrapper) {
        int totalCleaned = 0;
        
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            int cleaned = cleanMethod(methodWrapper);
            totalCleaned += cleaned;
        }
        
        if (totalCleaned > 0) {
            Run.log(classWrapper.getName() + " | Cleaned " + totalCleaned + " Colonial flow obfuscations");
        }
    }
    
    /**
     * Clean flow obfuscations in a method
     */
    private int cleanMethod(MethodWrapper methodWrapper) {
        MethodNode methodNode = methodWrapper.getMethodNode();
        int cleaned = 0;
        
        // First pass: Simplify sequence of GOTOs
        cleaned += simplifyGotoChains(methodNode);
        
        // Second pass: Remove redundant labels
        cleaned += removeRedundantLabels(methodNode);
        
        // Third pass: Remove useless conditional jumps
        cleaned += removeUselessConditionals(methodNode);
        
        // Fourth pass: Remove unreachable code blocks
        cleaned += removeUnreachableBlocks(methodNode);
        
        // Fifth pass: Clean fake returns
        cleaned += removeFakeReturns(methodNode);
        
        // Sixth pass: Simplify jump tables
        cleaned += simplifyJumpTables(methodNode);
        
        return cleaned;
    }
    
    /**
     * Simplify chains of GOTOs (A->B->C becomes A->C)
     */
    private int simplifyGotoChains(MethodNode methodNode) {
        int simplified = 0;
        boolean changed;
        
        do {
            changed = false;
            Map<LabelNode, LabelNode> redirects = new HashMap<>();
            
            // First pass: identify GOTO chains
            for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof JumpInsnNode && insn.getOpcode() == GOTO) {
                    JumpInsnNode gotoInsn = (JumpInsnNode) insn;
                    LabelNode target = gotoInsn.label;
                    
                    // Find what's after the target label
                    AbstractInsnNode afterLabel = target;
                    while (afterLabel != null && (afterLabel instanceof LabelNode || 
                                                afterLabel instanceof LineNumberNode || 
                                                afterLabel instanceof FrameNode)) {
                        afterLabel = afterLabel.getNext();
                    }
                    
                    // If the code after the label is another GOTO, this is a chain
                    if (afterLabel != null && afterLabel.getOpcode() == GOTO) {
                        JumpInsnNode chainedGoto = (JumpInsnNode) afterLabel;
                        redirects.put(target, chainedGoto.label);
                        changed = true;
                    }
                }
            }
            
            // Second pass: update all jumps using the redirects
            if (!redirects.isEmpty()) {
                for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn instanceof JumpInsnNode) {
                        JumpInsnNode jumpInsn = (JumpInsnNode) insn;
                        LabelNode target = jumpInsn.label;
                        
                        // If this jump's target is in our redirect map, update it
                        if (redirects.containsKey(target)) {
                            jumpInsn.label = redirects.get(target);
                            simplified++;
                        }
                    } else if (insn instanceof TableSwitchInsnNode) {
                        TableSwitchInsnNode tableSwitchInsn = (TableSwitchInsnNode) insn;
                        
                        // Update default target
                        if (redirects.containsKey(tableSwitchInsn.dflt)) {
                            tableSwitchInsn.dflt = redirects.get(tableSwitchInsn.dflt);
                            simplified++;
                        }
                        
                        // Update all case targets
                        for (int i = 0; i < tableSwitchInsn.labels.size(); i++) {
                            LabelNode caseLabel = tableSwitchInsn.labels.get(i);
                            if (redirects.containsKey(caseLabel)) {
                                tableSwitchInsn.labels.set(i, redirects.get(caseLabel));
                                simplified++;
                            }
                        }
                    } else if (insn instanceof LookupSwitchInsnNode) {
                        LookupSwitchInsnNode lookupSwitchInsn = (LookupSwitchInsnNode) insn;
                        
                        // Update default target
                        if (redirects.containsKey(lookupSwitchInsn.dflt)) {
                            lookupSwitchInsn.dflt = redirects.get(lookupSwitchInsn.dflt);
                            simplified++;
                        }
                        
                        // Update all case targets
                        for (int i = 0; i < lookupSwitchInsn.labels.size(); i++) {
                            LabelNode caseLabel = lookupSwitchInsn.labels.get(i);
                            if (redirects.containsKey(caseLabel)) {
                                lookupSwitchInsn.labels.set(i, redirects.get(caseLabel));
                                simplified++;
                            }
                        }
                    }
                }
            }
            
        } while (changed);
        
        return simplified;
    }
    
    /**
     * Remove labels that aren't used as jump targets
     */
    private int removeRedundantLabels(MethodNode methodNode) {
        int removed = 0;
        
        // First, identify all labels that are actually used as jump targets
        Set<LabelNode> usedLabels = new HashSet<>();
        
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof JumpInsnNode) {
                usedLabels.add(((JumpInsnNode) insn).label);
            } else if (insn instanceof TableSwitchInsnNode) {
                TableSwitchInsnNode switchInsn = (TableSwitchInsnNode) insn;
                usedLabels.add(switchInsn.dflt);
                usedLabels.addAll(switchInsn.labels);
            } else if (insn instanceof LookupSwitchInsnNode) {
                LookupSwitchInsnNode switchInsn = (LookupSwitchInsnNode) insn;
                usedLabels.add(switchInsn.dflt);
                usedLabels.addAll(switchInsn.labels);
            }
        }
        
        // Check try-catch blocks too
        if (methodNode.tryCatchBlocks != null) {
            for (TryCatchBlockNode tryCatch : methodNode.tryCatchBlocks) {
                usedLabels.add(tryCatch.start);
                usedLabels.add(tryCatch.end);
                usedLabels.add(tryCatch.handler);
            }
        }
        
        // Remove labels that aren't used
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Save next before potential removal
            
            if (insn instanceof LabelNode && !usedLabels.contains(insn)) {
                methodNode.instructions.remove(insn);
                removed++;
            }
            
            insn = next;
        }
        
        return removed;
    }
    
    /**
     * Remove useless conditional jumps (conditions that are always true/false)
     */
    private int removeUselessConditionals(MethodNode methodNode) {
        int removed = 0;
        
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Save next before potential modification
            
            if (insn instanceof JumpInsnNode && insn.getOpcode() != GOTO) {
                JumpInsnNode jumpInsn = (JumpInsnNode) insn;
                
                // Check conditions that are always true/false
                AbstractInsnNode prev1 = getPreviousRealInsn(insn);
                AbstractInsnNode prev2 = prev1 != null ? getPreviousRealInsn(prev1) : null;
                
                if (prev1 != null && prev2 != null && isConstantComparison(prev1, prev2)) {
                    boolean result = evaluateConstantCondition(prev1, prev2, jumpInsn.getOpcode());
                    
                    if (result) {
                        // Condition is always true - replace with GOTO
                        JumpInsnNode newJump = new JumpInsnNode(GOTO, jumpInsn.label);
                        methodNode.instructions.insertBefore(jumpInsn, newJump);
                        
                        // Remove the conditional and comparison operands
                        methodNode.instructions.remove(jumpInsn);
                        methodNode.instructions.remove(prev1);
                        methodNode.instructions.remove(prev2);
                        
                        removed++;
                        next = newJump.getNext();
                    } else {
                        // Condition is always false - remove the jump completely
                        methodNode.instructions.remove(jumpInsn);
                        methodNode.instructions.remove(prev1);
                        methodNode.instructions.remove(prev2);
                        
                        removed++;
                    }
                }
            }
            
            insn = next;
        }
        
        return removed;
    }
    
    /**
     * Check if two instructions form a constant comparison
     */
    private boolean isConstantComparison(AbstractInsnNode insn1, AbstractInsnNode insn2) {
        return isConstant(insn1) && isConstant(insn2);
    }
    
    /**
     * Evaluate a constant condition to determine if it's always true or false
     */
    private boolean evaluateConstantCondition(AbstractInsnNode val1Insn, AbstractInsnNode val2Insn, int opcode) {
        int val1 = getConstantValue(val1Insn);
        int val2 = getConstantValue(val2Insn);
        
        switch (opcode) {
            case IF_ICMPEQ: return val1 == val2;
            case IF_ICMPNE: return val1 != val2;
            case IF_ICMPLT: return val1 < val2;
            case IF_ICMPGE: return val1 >= val2;
            case IF_ICMPGT: return val1 > val2;
            case IF_ICMPLE: return val1 <= val2;
            default: return false;
        }
    }
    
    /**
     * Remove unreachable code blocks (code after GOTO, RETURN, or THROW)
     */
    private int removeUnreachableBlocks(MethodNode methodNode) {
        int removed = 0;
        
        // First identify all reachable instructions
        Set<AbstractInsnNode> reachable = new HashSet<>();
        Set<LabelNode> reachableLabels = new HashSet<>();
        
        // Start with the entry point
        markReachableCode(methodNode, methodNode.instructions.getFirst(), reachable, reachableLabels);
        
        // Mark try-catch blocks as reachable
        if (methodNode.tryCatchBlocks != null) {
            for (TryCatchBlockNode tryCatch : methodNode.tryCatchBlocks) {
                reachableLabels.add(tryCatch.start);
                reachableLabels.add(tryCatch.end);
                reachableLabels.add(tryCatch.handler);
            }
        }
        
        // Remove unreachable code
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Save before potential removal
            
            if (insn instanceof LabelNode) {
                // Keep all labels for safety
            } else if (!reachable.contains(insn) && !(insn instanceof LineNumberNode) && 
                      !(insn instanceof FrameNode)) {
                methodNode.instructions.remove(insn);
                removed++;
            }
            
            insn = next;
        }
        
        return removed;
    }
    
    /**
     * Recursively mark all reachable code
     */
    private void markReachableCode(MethodNode methodNode, AbstractInsnNode start, 
                                 Set<AbstractInsnNode> reachable, Set<LabelNode> reachableLabels) {
        AbstractInsnNode insn = start;
        
        while (insn != null) {
            // If we've already processed this instruction, stop to avoid cycles
            if (reachable.contains(insn)) {
                return;
            }
            
            // Mark this instruction as reachable
            reachable.add(insn);
            
            // Process based on instruction type
            if (insn instanceof JumpInsnNode) {
                JumpInsnNode jumpInsn = (JumpInsnNode) insn;
                LabelNode target = jumpInsn.label;
                reachableLabels.add(target);
                
                // For GOTO, continue from the target
                if (insn.getOpcode() == GOTO) {
                    // Find the target instruction
                    AbstractInsnNode targetInsn = findLabelNode(methodNode, target);
                    if (targetInsn != null) {
                        markReachableCode(methodNode, targetInsn, reachable, reachableLabels);
                    }
                    return; // No need to mark after GOTO
                }
                
                // For conditional jumps, mark both paths
                // First recursively mark the jump target
                AbstractInsnNode targetInsn = findLabelNode(methodNode, target);
                if (targetInsn != null) {
                    markReachableCode(methodNode, targetInsn, reachable, reachableLabels);
                }
                
                // Then continue marking the fall-through path
            } else if (insn instanceof TableSwitchInsnNode) {
                TableSwitchInsnNode switchInsn = (TableSwitchInsnNode) insn;
                
                // Mark default case
                reachableLabels.add(switchInsn.dflt);
                AbstractInsnNode defaultInsn = findLabelNode(methodNode, switchInsn.dflt);
                if (defaultInsn != null) {
                    markReachableCode(methodNode, defaultInsn, reachable, reachableLabels);
                }
                
                // Mark all other cases
                for (LabelNode caseLabel : switchInsn.labels) {
                    reachableLabels.add(caseLabel);
                    AbstractInsnNode caseInsn = findLabelNode(methodNode, caseLabel);
                    if (caseInsn != null) {
                        markReachableCode(methodNode, caseInsn, reachable, reachableLabels);
                    }
                }
                
                return; // No fall-through after switch
            } else if (insn instanceof LookupSwitchInsnNode) {
                LookupSwitchInsnNode switchInsn = (LookupSwitchInsnNode) insn;
                
                // Mark default case
                reachableLabels.add(switchInsn.dflt);
                AbstractInsnNode defaultInsn = findLabelNode(methodNode, switchInsn.dflt);
                if (defaultInsn != null) {
                    markReachableCode(methodNode, defaultInsn, reachable, reachableLabels);
                }
                
                // Mark all other cases
                for (LabelNode caseLabel : switchInsn.labels) {
                    reachableLabels.add(caseLabel);
                    AbstractInsnNode caseInsn = findLabelNode(methodNode, caseLabel);
                    if (caseInsn != null) {
                        markReachableCode(methodNode, caseInsn, reachable, reachableLabels);
                    }
                }
                
                return; // No fall-through after switch
            } else if ((insn.getOpcode() >= IRETURN && insn.getOpcode() <= RETURN) || 
                      insn.getOpcode() == ATHROW) {
                return; // Stop marking after return or throw
            }
            
            insn = insn.getNext();
        }
    }
    
    /**
     * Find a label node in the method instructions
     */
    private AbstractInsnNode findLabelNode(MethodNode methodNode, LabelNode target) {
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn == target) {
                return insn;
            }
        }
        return null;
    }
    
    /**
     * Remove fake returns (unreachable return statements)
     */
    private int removeFakeReturns(MethodNode methodNode) {
        int removed = 0;
        
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Save before potential removal
            
            // Check for return statements
            if (insn.getOpcode() >= IRETURN && insn.getOpcode() <= RETURN) {
                // Check if this return is reachable
                boolean reachable = isReturnReachable(methodNode, insn);
                
                if (!reachable) {
                    // Remove the return and any preceding instructions that prepare the return value
                    removed += removeUnreachableReturn(methodNode, insn);
                }
            }
            
            insn = next;
        }
        
        return removed;
    }
    
    /**
     * Check if a return statement is actually reachable
     */
    private boolean isReturnReachable(MethodNode methodNode, AbstractInsnNode returnInsn) {
        // This would require proper control flow analysis
        // As a simplification, we'll assume all returns are reachable
        // TODO: Implement more sophisticated reachability analysis
        return true;
    }
    
    /**
     * Remove an unreachable return statement and its setup code
     */
    private int removeUnreachableReturn(MethodNode methodNode, AbstractInsnNode returnInsn) {
        // Colonial often adds fake returns with constants, so check for that pattern
        AbstractInsnNode prev = getPreviousRealInsn(returnInsn);
        if (prev != null && isConstant(prev)) {
            methodNode.instructions.remove(prev);
            methodNode.instructions.remove(returnInsn);
            return 2;
        } else {
            methodNode.instructions.remove(returnInsn);
            return 1;
        }
    }
    
    /**
     * Simplify jump tables (TABLESWITCH and LOOKUPSWITCH)
     */
    private int simplifyJumpTables(MethodNode methodNode) {
        int simplified = 0;
        
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Save before potential modification
            
            if (insn instanceof TableSwitchInsnNode) {
                TableSwitchInsnNode tableSwitchInsn = (TableSwitchInsnNode) insn;
                
                // Check for constant switch value
                AbstractInsnNode prev = getPreviousRealInsn(insn);
                if (prev != null && isConstant(prev)) {
                    int value = getConstantValue(prev);
                    
                    // Determine which case will be taken
                    LabelNode targetLabel;
                    if (value >= tableSwitchInsn.min && value <= tableSwitchInsn.max) {
                        int index = value - tableSwitchInsn.min;
                        targetLabel = tableSwitchInsn.labels.get(index);
                    } else {
                        targetLabel = tableSwitchInsn.dflt;
                    }
                    
                    // Replace with a direct GOTO
                    JumpInsnNode gotoInsn = new JumpInsnNode(GOTO, targetLabel);
                    methodNode.instructions.insertBefore(prev, gotoInsn);
                    
                    // Remove the switch and its value
                    methodNode.instructions.remove(prev);
                    methodNode.instructions.remove(insn);
                    
                    simplified++;
                    next = gotoInsn.getNext();
                }
            } else if (insn instanceof LookupSwitchInsnNode) {
                LookupSwitchInsnNode lookupSwitchInsn = (LookupSwitchInsnNode) insn;
                
                // Check for constant switch value
                AbstractInsnNode prev = getPreviousRealInsn(insn);
                if (prev != null && isConstant(prev)) {
                    int value = getConstantValue(prev);
                    
                    // Determine which case will be taken
                    LabelNode targetLabel = lookupSwitchInsn.dflt;
                    for (int i = 0; i < lookupSwitchInsn.keys.size(); i++) {
                        if (lookupSwitchInsn.keys.get(i) == value) {
                            targetLabel = lookupSwitchInsn.labels.get(i);
                            break;
                        }
                    }
                    
                    // Replace with a direct GOTO
                    JumpInsnNode gotoInsn = new JumpInsnNode(GOTO, targetLabel);
                    methodNode.instructions.insertBefore(prev, gotoInsn);
                    
                    // Remove the switch and its value
                    methodNode.instructions.remove(prev);
                    methodNode.instructions.remove(insn);
                    
                    simplified++;
                    next = gotoInsn.getNext();
                }
            }
            
            insn = next;
        }
        
        return simplified;
    }
    
    /**
     * Check if an instruction is a constant
     */
    private boolean isConstant(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        return (opcode >= ICONST_M1 && opcode <= ICONST_5) ||
               opcode == BIPUSH || 
               opcode == SIPUSH ||
               (insn instanceof LdcInsnNode && ((LdcInsnNode) insn).cst instanceof Integer);
    }
    
    /**
     * Get the value of a constant instruction
     */
    private int getConstantValue(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        
        if (opcode >= ICONST_M1 && opcode <= ICONST_5) {
            return opcode - ICONST_0;
        } else if (opcode == BIPUSH || opcode == SIPUSH) {
            return ((IntInsnNode) insn).operand;
        } else if (insn instanceof LdcInsnNode && ((LdcInsnNode) insn).cst instanceof Integer) {
            return (Integer) ((LdcInsnNode) insn).cst;
        }
        
        throw new IllegalArgumentException("Not a constant instruction: " + insn.getOpcode());
    }
    
    /**
     * Get the previous real instruction (skip labels, line numbers, etc.)
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