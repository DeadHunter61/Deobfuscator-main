package dead.owner.deobf.transformers.colonial;

import dead.owner.deobf.Run;
import dead.owner.deobf.utils.wrapper.ClassWrapper;
import dead.owner.deobf.utils.wrapper.MethodWrapper;
import dead.owner.deobf.transformers.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.util.*;

/**
 * Transformer to restore normal control flow from Colonial's exception-based flow obfuscation.
 * Colonial Obfuscator often uses exception handling to obfuscate control flow, similar to
 * SkidFuscator but with its own unique patterns.
 */
public class ColonialExceptionRestorer implements Transformer, Opcodes {
    
    @Override
    public void transform(ClassWrapper classWrapper) {
        int totalRestored = 0;
        
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            int restored = restoreExceptionBasedFlow(methodWrapper);
            totalRestored += restored;
        }
        
        if (totalRestored > 0) {
            Run.log(classWrapper.getName() + " | Restored " + totalRestored + " exception-based control flows");
        }
    }
    
    /**
     * Restore normal control flow from Colonial's exception-based flow obfuscation
     */
    private int restoreExceptionBasedFlow(MethodWrapper methodWrapper) {
        MethodNode methodNode = methodWrapper.getMethodNode();
        
        // Skip methods without try-catch blocks
        if (methodNode.tryCatchBlocks == null || methodNode.tryCatchBlocks.isEmpty()) {
            return 0;
        }
        
        int restored = 0;
        List<TryCatchBlockNode> blocksToRemove = new ArrayList<>();
        Map<LabelNode, LabelNode> jumpsToReplace = new HashMap<>();
        
        // Analyze each try-catch block for flow obfuscation patterns
        for (TryCatchBlockNode tryCatch : methodNode.tryCatchBlocks) {
            if (isFlowObfuscationTryCatch(methodNode, tryCatch)) {
                LabelNode targetLabel = findRealFlowTarget(methodNode, tryCatch.handler);
                
                if (targetLabel != null) {
                    blocksToRemove.add(tryCatch);
                    jumpsToReplace.put(tryCatch.start, targetLabel);
                    restored++;
                }
            }
        }
        
        // Remove identified blocks and fix jumps
        methodNode.tryCatchBlocks.removeAll(blocksToRemove);
        
        // Replace jumps to the try block with direct jumps to the handler target
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof JumpInsnNode) {
                JumpInsnNode jumpInsn = (JumpInsnNode) insn;
                
                if (jumpsToReplace.containsKey(jumpInsn.label)) {
                    jumpInsn.label = jumpsToReplace.get(jumpInsn.label);
                }
            }
        }
        
        // Remove throw instructions from try blocks
        for (Map.Entry<LabelNode, LabelNode> entry : jumpsToReplace.entrySet()) {
            cleanupTryBlock(methodNode, entry.getKey());
        }
        
        return restored;
    }
    
    /**
     * Check if a try-catch block is likely to be a control flow obfuscation
     */
    private boolean isFlowObfuscationTryCatch(MethodNode methodNode, TryCatchBlockNode tryCatch) {
        // Check if the try block always throws an exception
        boolean hasThrow = false;
        int instructionCount = 0;
        
        for (AbstractInsnNode insn = findLabelInstruction(methodNode, tryCatch.start);
             insn != null && insn != findLabelInstruction(methodNode, tryCatch.end);
             insn = insn.getNext()) {
            
            if (insn.getOpcode() == ATHROW) {
                hasThrow = true;
            }
            
            if (!(insn instanceof LabelNode) && 
                !(insn instanceof LineNumberNode) && 
                !(insn instanceof FrameNode)) {
                instructionCount++;
            }
        }
        
        // If the try block is small and always throws, it might be flow obfuscation
        if (!hasThrow || instructionCount > 10) {
            return false;
        }
        
        // Check the handler for common patterns
        boolean handlerPopsException = false;
        
        for (AbstractInsnNode insn = findLabelInstruction(methodNode, tryCatch.handler);
             insn != null;
             insn = insn.getNext()) {
            
            if (insn.getOpcode() == ASTORE || insn.getOpcode() == POP) {
                handlerPopsException = true;
                break;
            }
            
            // If we hit a real instruction before the pop, it's probably not flow obfuscation
            if (!(insn instanceof LabelNode) && 
                !(insn instanceof LineNumberNode) && 
                !(insn instanceof FrameNode)) {
                break;
            }
        }
        
        return handlerPopsException;
    }
    
    /**
     * Find the real control flow target from a try-catch handler
     */
    private LabelNode findRealFlowTarget(MethodNode methodNode, LabelNode handlerLabel) {
        // Skip the exception storage (ASTORE) or pop (POP)
        AbstractInsnNode current = findLabelInstruction(methodNode, handlerLabel);
        
        while (current != null) {
            if (current.getOpcode() == ASTORE || current.getOpcode() == POP) {
                current = current.getNext();
                
                // Skip any more frame nodes, labels, etc.
                while (current != null && (current instanceof LabelNode || 
                                         current instanceof LineNumberNode || 
                                         current instanceof FrameNode)) {
                    current = current.getNext();
                }
                
                // If the next real instruction is a GOTO, that's our real target
                if (current != null && current.getOpcode() == GOTO) {
                    return ((JumpInsnNode) current).label;
                }
                
                // If it's not a GOTO, but still an instruction, that's the start of real code
                if (current != null && !(current instanceof LabelNode) && 
                    !(current instanceof LineNumberNode) && 
                    !(current instanceof FrameNode)) {
                    
                    // Find the closest preceding label
                    LabelNode closestLabel = findClosestPrecedingLabel(methodNode, current);
                    if (closestLabel != null) {
                        return closestLabel;
                    }
                }
                
                break;
            }
            
            current = current.getNext();
        }
        
        return null;
    }
    
    /**
     * Find the closest label that precedes the given instruction
     */
    private LabelNode findClosestPrecedingLabel(MethodNode methodNode, AbstractInsnNode target) {
        AbstractInsnNode current = target;
        
        while (current != null) {
            if (current instanceof LabelNode) {
                return (LabelNode) current;
            }
            current = current.getPrevious();
        }
        
        return null;
    }
    
    /**
     * Find the actual instruction for a given label
     */
    private AbstractInsnNode findLabelInstruction(MethodNode methodNode, LabelNode label) {
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn == label) {
                return insn;
            }
        }
        return null;
    }
    
    /**
     * Clean up instructions in a try block that's being removed
     */
    private void cleanupTryBlock(MethodNode methodNode, LabelNode startLabel) {
        // Find throw instructions in the try block and remove them
        boolean inTryBlock = false;
        List<AbstractInsnNode> toRemove = new ArrayList<>();
        
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn == startLabel) {
                inTryBlock = true;
            }
            
            if (inTryBlock) {
                // If this is a throw, mark it and all instructions leading to it for removal
                if (insn.getOpcode() == ATHROW) {
                    // Find all instructions in the throw sequence
                    List<AbstractInsnNode> throwSequence = findThrowSequence(insn);
                    toRemove.addAll(throwSequence);
                }
                
                // If we've hit a jump, we're probably no longer in the try block
                if (insn instanceof JumpInsnNode) {
                    inTryBlock = false;
                }
            }
        }
        
        // Remove all marked instructions
        for (AbstractInsnNode insn : toRemove) {
            methodNode.instructions.remove(insn);
        }
    }
    
    /**
     * Find all instructions in a throw sequence
     */
    private List<AbstractInsnNode> findThrowSequence(AbstractInsnNode throwInsn) {
        List<AbstractInsnNode> sequence = new ArrayList<>();
        sequence.add(throwInsn);
        
        // Typically, a throw sequence consists of:
        // NEW exception
        // DUP
        // (optional) arguments for constructor
        // INVOKESPECIAL constructor
        // ATHROW
        
        AbstractInsnNode current = throwInsn.getPrevious();
        while (current != null) {
            if (current instanceof MethodInsnNode && 
                ((MethodInsnNode) current).name.equals("<init>")) {
                // Found the constructor call
                sequence.add(0, current);
                break;
            }
            
            if (!(current instanceof LabelNode) && 
                !(current instanceof LineNumberNode) && 
                !(current instanceof FrameNode)) {
                sequence.add(0, current);
            }
            
            current = current.getPrevious();
        }
        
        // Go back a bit further to find the NEW and DUP
        if (current != null) {
            current = current.getPrevious();
            while (current != null && sequence.size() < 10) { // Limit to avoid capturing too much
                if (current.getOpcode() == NEW) {
                    sequence.add(0, current);
                    break;
                }
                
                if (!(current instanceof LabelNode) && 
                    !(current instanceof LineNumberNode) && 
                    !(current instanceof FrameNode)) {
                    sequence.add(0, current);
                }
                
                current = current.getPrevious();
            }
        }
        
        return sequence;
    }
}