package dead.owner.deobf.transformers;

import dead.owner.deobf.Run;
import dead.owner.deobf.utils.wrapper.ClassWrapper;
import dead.owner.deobf.utils.wrapper.MethodWrapper;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.util.*;

/**
 * Transformer to remove control flow obfuscation caused by the xufptsyuqyfygcsb class
 */
public class XufptsyuqCleaner implements Transformer, Opcodes {
    
    private static final String CONTROL_FLOW_CLASS = "iakwerymudfxddrx/xufptsyuqyfygcsb";
    private static final String[] CONTROL_FLOW_METHODS = {
        "nudzrwhrluemgkta", // Main control flow method
        "xhrwevfwjdjhyfeh", // Used for condition checks
        "ttsgbhaeitkbgppm"  // Used in try-catch blocks
    };
    
    @Override
    public void transform(ClassWrapper classWrapper) {
        int totalRemoved = 0;
        boolean classModified = false;
        
        // First pass: identify control flow patterns and logic
        Map<String, Map<Integer, Integer>> switchMaps = new HashMap<>();
        
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            MethodNode methodNode = methodWrapper.getMethodNode();
            
            // Skip empty methods
            if (methodNode.instructions.size() == 0) continue;
            
            // Identify control flow structures
            totalRemoved += identifyControlFlowStructures(methodWrapper, switchMaps);
        }
        
        // Second pass: replace control flow with direct paths
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            classModified |= simplifyControlFlow(methodWrapper, switchMaps);
        }
        
        if (totalRemoved > 0) {
            Run.log(classWrapper.getName() + " | Removed " + totalRemoved + " control flow obfuscations");
            Run.log(classWrapper.getName() + " | Simplified control flow paths");
        }
    }
    
    /**
     * Identify control flow structures in a method
     */
    private int identifyControlFlowStructures(MethodWrapper methodWrapper, Map<String, Map<Integer, Integer>> switchMaps) {
        MethodNode methodNode = methodWrapper.getMethodNode();
        int removed = 0;
        
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            // Look for xufptsyuqyfygcsb method calls that control the flow
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                if (isControlFlowMethod(methodInsn)) {
                    // Find the preceding instructions that push the hash/state value
                    AbstractInsnNode prev = getPreviousRealInsn(insn);
                    if (prev != null && isPushingIntValue(prev)) {
                        int hashValue = getIntValue(prev);
                        
                        // Find the TABLESWITCH/LOOKUPSWITCH that follows
                        AbstractInsnNode switchNode = findSwitchAfter(insn);
                        if (switchNode instanceof TableSwitchInsnNode || switchNode instanceof LookupSwitchInsnNode) {
                            // Map the control value to switch targets
                            recordSwitchTargets(methodWrapper.getName() + methodNode.desc, hashValue, switchNode);
                            removed++;
                        }
                    }
                }
            }
        }
        
        return removed;
    }
    
    /**
     * Record switch targets for a given control flow hash
     */
    private void recordSwitchTargets(String methodId, int hashValue, AbstractInsnNode switchNode) {
        Map<Integer, Integer> switchTargets = new HashMap<>();
        
        if (switchNode instanceof TableSwitchInsnNode) {
            TableSwitchInsnNode tableSwitchNode = (TableSwitchInsnNode) switchNode;
            int index = 0;
            for (LabelNode target : tableSwitchNode.labels) {
                switchTargets.put(tableSwitchNode.min + index, indexOfLabel(switchNode, target));
                index++;
            }
            switchTargets.put(-1, indexOfLabel(switchNode, tableSwitchNode.dflt)); // Default case
        } else if (switchNode instanceof LookupSwitchInsnNode) {
            LookupSwitchInsnNode lookupSwitchNode = (LookupSwitchInsnNode) switchNode;
            int index = 0;
            for (Integer key : lookupSwitchNode.keys) {
                switchTargets.put(key, indexOfLabel(switchNode, lookupSwitchNode.labels.get(index)));
                index++;
            }
            switchTargets.put(-1, indexOfLabel(switchNode, lookupSwitchNode.dflt)); // Default case
        }
    }
    
    /**
     * Get the index offset of a label relative to a switch instruction
     */
    private int indexOfLabel(AbstractInsnNode switchNode, LabelNode label) {
        AbstractInsnNode current = switchNode.getNext();
        int index = 1;
        
        while (current != null) {
            if (current == label) {
                return index;
            }
            index++;
            current = current.getNext();
        }
        
        return -1; // Not found
    }
    
    /**
     * Simplify the control flow by removing unnecessary branches
     */
    private boolean simplifyControlFlow(MethodWrapper methodWrapper, Map<String, Map<Integer, Integer>> switchMaps) {
        MethodNode methodNode = methodWrapper.getMethodNode();
        boolean modified = false;
        
        // Look for switch statements that can be simplified
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Store next before potential modification
            
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                if (isControlFlowMethod(methodInsn)) {
                    AbstractInsnNode prev = getPreviousRealInsn(insn);
                    AbstractInsnNode switchNode = findSwitchAfter(insn);
                    
                    if (prev != null && isPushingIntValue(prev) && 
                        (switchNode instanceof TableSwitchInsnNode || switchNode instanceof LookupSwitchInsnNode)) {
                        // Remove the control flow pattern
                        removeInstructionsBetween(methodNode.instructions, prev, switchNode);
                        modified = true;
                    }
                }
            } else if ((insn instanceof TableSwitchInsnNode || insn instanceof LookupSwitchInsnNode) &&
                       isPatchableSwitchStatement(insn)) {
                replaceWithDirectJump(methodNode.instructions, insn);
                modified = true;
            }
            
            insn = next;
        }
        
        // Remove unnecessary try-catch blocks
        removeUnnecessaryTryCatchBlocks(methodNode);
        
        return modified;
    }
    
    /**
     * Check if a switch statement can be patched (replaced with direct jumps)
     */
    private boolean isPatchableSwitchStatement(AbstractInsnNode switchNode) {
        // This is a simplification - in a real deobfuscator, you would analyze
        // the switch statement to determine if it's part of the obfuscation
        AbstractInsnNode prev = getPreviousRealInsn(switchNode);
        if (prev instanceof MethodInsnNode) {
            MethodInsnNode methodInsn = (MethodInsnNode) prev;
            return isControlFlowMethod(methodInsn);
        }
        return false;
    }
    
    /**
     * Replace a switch statement with a direct jump to the most likely target
     */
    private void replaceWithDirectJump(InsnList instructions, AbstractInsnNode switchNode) {
        LabelNode targetLabel = null;
        
        if (switchNode instanceof TableSwitchInsnNode) {
            TableSwitchInsnNode tableSwitchNode = (TableSwitchInsnNode) switchNode;
            // For simplicity, jump to the first case (you could make this smarter)
            targetLabel = !tableSwitchNode.labels.isEmpty() ? tableSwitchNode.labels.get(0) : tableSwitchNode.dflt;
        } else if (switchNode instanceof LookupSwitchInsnNode) {
            LookupSwitchInsnNode lookupSwitchNode = (LookupSwitchInsnNode) switchNode;
            targetLabel = !lookupSwitchNode.labels.isEmpty() ? lookupSwitchNode.labels.get(0) : lookupSwitchNode.dflt;
        }
        
        if (targetLabel != null) {
            // Replace the switch with a direct GOTO
            JumpInsnNode gotoInsn = new JumpInsnNode(GOTO, targetLabel);
            instructions.insertBefore(switchNode, gotoInsn);
            instructions.remove(switchNode);
        }
    }
    
    /**
     * Remove unnecessary try-catch blocks that were part of the obfuscation
     */
    private void removeUnnecessaryTryCatchBlocks(MethodNode methodNode) {
        if (methodNode.tryCatchBlocks == null) return;
        
        Iterator<TryCatchBlockNode> iterator = methodNode.tryCatchBlocks.iterator();
        while (iterator.hasNext()) {
            TryCatchBlockNode tryCatchBlock = iterator.next();
            
            // Check if this try-catch is just for obfuscation
            if (isObfuscationTryCatch(tryCatchBlock)) {
                iterator.remove();
            }
        }
    }
    
    /**
     * Check if a try-catch block is part of the obfuscation
     */
    private boolean isObfuscationTryCatch(TryCatchBlockNode tryCatchBlock) {
        // This is a simplification - in a real deobfuscator, you would analyze
        // the try-catch more thoroughly
        return tryCatchBlock.type != null && 
             (tryCatchBlock.type.equals("java/lang/IllegalAccessException") ||
              tryCatchBlock.type.equals("java/lang/RuntimeException") ||
              tryCatchBlock.type.equals("java/lang/Error"));
    }
    
    /**
     * Check if an instruction is a control flow method call
     */
    private boolean isControlFlowMethod(MethodInsnNode methodInsn) {
        if (!methodInsn.owner.equals(CONTROL_FLOW_CLASS)) {
            return false;
        }
        
        for (String method : CONTROL_FLOW_METHODS) {
            if (methodInsn.name.equals(method)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Find the switch instruction after a given instruction
     */
    private AbstractInsnNode findSwitchAfter(AbstractInsnNode insn) {
        AbstractInsnNode current = insn.getNext();
        while (current != null) {
            if (current instanceof TableSwitchInsnNode || current instanceof LookupSwitchInsnNode) {
                return current;
            }
            
            // Don't go too far
            if (current instanceof JumpInsnNode || 
                current instanceof MethodInsnNode || 
                current instanceof InsnNode && 
                (current.getOpcode() >= IRETURN && current.getOpcode() <= RETURN)) {
                break;
            }
            
            current = current.getNext();
        }
        return null;
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
     * Remove all instructions between start and end (inclusive)
     */
    private void removeInstructionsBetween(InsnList instructions, AbstractInsnNode start, AbstractInsnNode end) {
        AbstractInsnNode current = start;
        while (current != end) {
            AbstractInsnNode toRemove = current;
            current = current.getNext();
            instructions.remove(toRemove);
        }
        instructions.remove(end);
    }
}