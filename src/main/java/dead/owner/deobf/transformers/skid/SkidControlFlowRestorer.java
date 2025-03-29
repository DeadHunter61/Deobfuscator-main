package dead.owner.deobf.transformers.skid;

import dead.owner.deobf.Run;
import dead.owner.deobf.utils.wrapper.ClassWrapper;
import dead.owner.deobf.utils.wrapper.MethodWrapper;
import dead.owner.deobf.transformers.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.util.*;

/**
 * Transformer to restore control flow obfuscated by SkidFuscator.
 * SkidFuscator uses several techniques to obfuscate control flow:
 * 1. Exception handling to divert execution
 * 2. Hash-based conditional jumps
 * 3. Additional unnecessary basic blocks
 */
public class SkidControlFlowRestorer implements Transformer, Opcodes {
    
    // Driver class name used by SkidFuscator
    private static final String DRIVER_CLASS = "skid/Driver";
    
    // Names of methods used by SkidFuscator to handle control flow
    private static final String[] CONTROL_FLOW_METHODS = {
        "get", "add", "checkType", "hash"
    };
    
    @Override
    public void transform(ClassWrapper classWrapper) {
        boolean classModified = false;
        int totalRestored = 0;
        
        // Find and fix driver class references if this is the driver class
        if (isDriverClass(classWrapper)) {
            Run.log(classWrapper.getName() + " | Identified SkidFuscator driver class");
            classModified = true;
        }
        
        // Process each method to restore control flow
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            int restored = restoreControlFlow(methodWrapper);
            totalRestored += restored;
            
            if (restored > 0) {
                classModified = true;
            }
        }
        
        if (classModified) {
            Run.log(classWrapper.getName() + " | Restored " + totalRestored + " control flow obfuscations");
        }
    }
    
    /**
     * Check if this is a SkidFuscator driver class
     */
    private boolean isDriverClass(ClassWrapper classWrapper) {
        // Check for unique signatures of the driver class
        boolean hasGetMethod = false;
        boolean hasAddMethod = false;
        
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            if (methodWrapper.getName().equals("get") && 
                methodWrapper.getDescriptor().equals("(Ljava/lang/String;)I")) {
                hasGetMethod = true;
            } else if (methodWrapper.getName().equals("add") && 
                     methodWrapper.getDescriptor().equals("(Ljava/lang/String;I)V")) {
                hasAddMethod = true;
            }
        }
        
        return hasGetMethod && hasAddMethod;
    }
    
    /**
     * Restore control flow in a method
     */
    private int restoreControlFlow(MethodWrapper methodWrapper) {
        MethodNode methodNode = methodWrapper.getMethodNode();
        int restored = 0;
        
        // First pass: locate and simplify exception-based control flow
        restored += restoreExceptionBasedControlFlow(methodNode);
        
        // Second pass: locate and simplify hash-based conditionals
        restored += restoreHashBasedConditionals(methodNode);
        
        // Third pass: remove unnecessary switch statements
        restored += restoreObfuscatedSwitches(methodNode);
        
        return restored;
    }
    
    /**
     * Restore exception-based control flow (BasicRangeTransformer in SkidFuscator)
     */
    private int restoreExceptionBasedControlFlow(MethodNode methodNode) {
        if (methodNode.tryCatchBlocks == null || methodNode.tryCatchBlocks.isEmpty()) {
            return 0;
        }
        
        int restored = 0;
        List<TryCatchBlockNode> blocksToRemove = new ArrayList<>();
        Map<LabelNode, LabelNode> jumpsToReplace = new HashMap<>();
        
        // Identify try-catch blocks used for control flow obfuscation
        for (TryCatchBlockNode tryCatchBlock : methodNode.tryCatchBlocks) {
            // Look for the specific pattern:
            // 1. Small try block that always throws an exception
            // 2. Catch handler that pops the exception and jumps to the target
            
            if (isObfuscatedExceptionRange(methodNode, tryCatchBlock)) {
                LabelNode targetLabel = findHandlerTarget(methodNode, tryCatchBlock.handler);
                if (targetLabel != null) {
                    // Mark this block for removal and record the jump replacement
                    blocksToRemove.add(tryCatchBlock);
                    jumpsToReplace.put(tryCatchBlock.start, targetLabel);
                    restored++;
                }
            }
        }
        
        // Remove identified try-catch blocks
        methodNode.tryCatchBlocks.removeAll(blocksToRemove);
        
        // Replace jumps to the try block with direct jumps to the target
        if (!jumpsToReplace.isEmpty()) {
            for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
                AbstractInsnNode next = insn.getNext(); // Store next before potential modification
                
                if (insn instanceof JumpInsnNode) {
                    JumpInsnNode jumpInsn = (JumpInsnNode) insn;
                    if (jumpsToReplace.containsKey(jumpInsn.label)) {
                        jumpInsn.label = jumpsToReplace.get(jumpInsn.label);
                    }
                }
                
                insn = next;
            }
            
            // Remove the throw instructions in the try blocks
            for (Map.Entry<LabelNode, LabelNode> entry : jumpsToReplace.entrySet()) {
                removeThrowSequence(methodNode, entry.getKey());
            }
        }
        
        return restored;
    }
    
    /**
     * Check if a try-catch block is likely to be an obfuscated control flow
     */
    private boolean isObfuscatedExceptionRange(MethodNode methodNode, TryCatchBlockNode tryCatchBlock) {
        // Look for a small try block that contains a throw statement
        boolean hasThrow = false;
        int instructionCount = 0;
        
        AbstractInsnNode current = tryCatchBlock.start;
        while (current != tryCatchBlock.end && current != null) {
            if (current.getOpcode() == ATHROW) {
                hasThrow = true;
            }
            
            if (!(current instanceof LabelNode) && 
                !(current instanceof LineNumberNode) && 
                !(current instanceof FrameNode)) {
                instructionCount++;
            }
            
            current = current.getNext();
        }
        
        // The block should have a throw and be relatively small
        if (!hasThrow || instructionCount > 10) {
            return false;
        }
        
        // Check if the handler pops the exception (common pattern)
        current = tryCatchBlock.handler;
        while (current != null) {
            if (current.getOpcode() == POP) {
                return true;
            }
            
            // Don't go too far
            if (current.getOpcode() == GOTO || 
                (current.getOpcode() >= IRETURN && current.getOpcode() <= RETURN) || 
                current.getOpcode() == ATHROW) {
                break;
            }
            
            current = current.getNext();
        }
        
        return false;
    }
    
    /**
     * Find the target of an exception handler
     */
    private LabelNode findHandlerTarget(MethodNode methodNode, LabelNode handlerLabel) {
        AbstractInsnNode current = handlerLabel;
        
        // Skip past the exception store and pop if present
        while (current != null) {
            if (current.getOpcode() == ASTORE || current.getOpcode() == POP) {
                current = current.getNext();
                continue;
            }
            
            if (current.getOpcode() == GOTO) {
                return ((JumpInsnNode) current).label;
            }
            
            // Skip frames and labels
            if (current instanceof LabelNode || 
                current instanceof LineNumberNode || 
                current instanceof FrameNode) {
                current = current.getNext();
                continue;
            }
            
            // If we reach here, it's not a simple handler pattern
            break;
        }
        
        return null;
    }
    
    /**
     * Remove a throw instruction sequence
     */
    private void removeThrowSequence(MethodNode methodNode, LabelNode startLabel) {
        AbstractInsnNode current = startLabel;
        List<AbstractInsnNode> toRemove = new ArrayList<>();
        
        // Find the sequence that leads to ATHROW
        while (current != null) {
            if (current.getOpcode() == ATHROW) {
                // Found the throw, now collect all instructions in the sequence
                AbstractInsnNode prev = current;
                while (prev != startLabel) {
                    if (!(prev instanceof LabelNode) && 
                        !(prev instanceof LineNumberNode) && 
                        !(prev instanceof FrameNode)) {
                        toRemove.add(0, prev);
                    }
                    prev = prev.getPrevious();
                }
                break;
            }
            
            // If we reach a jump, something else is going on
            if (current instanceof JumpInsnNode) {
                break;
            }
            
            current = current.getNext();
        }
        
        // Remove the instructions
        for (AbstractInsnNode insn : toRemove) {
            methodNode.instructions.remove(insn);
        }
    }
    
    /**
     * Restore hash-based conditionals (BasicConditionTransformer in SkidFuscator)
     */
    private int restoreHashBasedConditionals(MethodNode methodNode) {
        int restored = 0;
        
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Store next before potential modification
            
            // Look for SkidFuscator's hash-based conditional pattern
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                
                // Check for calls to hash generating methods
                if (methodInsn.owner.equals(DRIVER_CLASS) || 
                    methodInsn.name.equals("get") || 
                    methodInsn.name.equals("hash")) {
                    
                    // Look for the following conditional jump that uses this hash
                    AbstractInsnNode conditional = findConditionalAfter(insn);
                    if (conditional instanceof JumpInsnNode) {
                        // Simplify the conditional by making it direct
                        methodNode.instructions.remove(insn); // Remove the hash call
                        restored++;
                    }
                }
            }
            
            insn = next;
        }
        
        return restored;
    }
    
    /**
     * Find a conditional jump after an instruction
     */
    private AbstractInsnNode findConditionalAfter(AbstractInsnNode start) {
        AbstractInsnNode current = start.getNext();
        
        // Skip past any comparison setup
        while (current != null) {
            if (current instanceof JumpInsnNode) {
                int opcode = current.getOpcode();
                if (opcode >= IFEQ && opcode <= IF_ACMPNE) {
                    return current;
                }
            }
            
            // Don't go too far
            if (current.getOpcode() == GOTO || 
                (current.getOpcode() >= IRETURN && current.getOpcode() <= RETURN) || 
                current.getOpcode() == ATHROW) {
                break;
            }
            
            current = current.getNext();
        }
        
        return null;
    }
    
    /**
     * Restore obfuscated switches (SwitchTransformer in SkidFuscator)
     */
    private int restoreObfuscatedSwitches(MethodNode methodNode) {
        int restored = 0;
        
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Store next before potential modification
            
            // Look for XOR operations followed by LOOKUPSWITCH or TABLESWITCH
            if (insn.getOpcode() == IXOR) {
                AbstractInsnNode switchInsn = findSwitchAfter(insn);
                if (switchInsn != null) {
                    // This is likely an obfuscated switch
                    // We'll simplify it by removing the XOR
                    methodNode.instructions.remove(insn);
                    restored++;
                }
            }
            
            // Look for hash operations before switches
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                if (methodInsn.owner.equals(DRIVER_CLASS) && 
                    Arrays.asList(CONTROL_FLOW_METHODS).contains(methodInsn.name)) {
                    
                    AbstractInsnNode switchInsn = findSwitchAfter(insn);
                    if (switchInsn != null) {
                        // This is likely an obfuscated switch
                        methodNode.instructions.remove(insn);
                        restored++;
                    }
                }
            }
            
            insn = next;
        }
        
        return restored;
    }
    
    /**
     * Find a switch instruction after an instruction
     */
    private AbstractInsnNode findSwitchAfter(AbstractInsnNode start) {
        AbstractInsnNode current = start.getNext();
        
        while (current != null) {
            if (current instanceof TableSwitchInsnNode || current instanceof LookupSwitchInsnNode) {
                return current;
            }
            
            // Don't go too far
            if (current instanceof JumpInsnNode || 
                (current.getOpcode() >= IRETURN && current.getOpcode() <= RETURN) || 
                current.getOpcode() == ATHROW) {
                break;
            }
            
            current = current.getNext();
        }
        
        return null;
    }
}