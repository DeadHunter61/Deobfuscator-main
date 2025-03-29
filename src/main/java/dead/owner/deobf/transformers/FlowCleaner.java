package dead.owner.deobf.transformers;

import dead.owner.deobf.Run;
import dead.owner.deobf.utils.wrapper.ClassWrapper;
import dead.owner.deobf.utils.wrapper.MethodWrapper;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

/**
 * Transformer to remove flow obfuscation (dead code, useless instructions)
 */
public class FlowCleaner implements Transformer, Opcodes {
    
    @Override
    public void transform(ClassWrapper classWrapper) {
        int totalRemoved = 0;
        
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            totalRemoved += cleanMethod(methodWrapper);
        }
        
        if (totalRemoved > 0) {
            Run.log(classWrapper.getName() + " | Removed " + totalRemoved + " flow obfuscation sequences");
        }
    }
    
    /**
     * Remove dead code from a method
     * 
     * @return Number of code sequences removed
     */
    private int cleanMethod(MethodWrapper methodWrapper) {
        int removed = 0;
        InsnList instructions = methodWrapper.getInstructions();
        boolean modified;
        
        // Repeat until no more changes
        do {
            modified = false;
            
            for (AbstractInsnNode insn = instructions.getFirst(); insn != null; ) {
                AbstractInsnNode next = insn.getNext();
                
                // Check for push-pop pattern: push value then immediately pop it
                if (isPushPopPattern(insn)) {
                    AbstractInsnNode endNode = findEndOfPushPopSequence(insn);
                    if (endNode != null) {
                        removeInstructions(instructions, insn, endNode);
                        modified = true;
                        removed++;
                    }
                }
                
                // Check for string push-pop: load string then pop it
                else if (isStringPushPopPattern(insn)) {
                    AbstractInsnNode endNode = findEndOfStringPushPopSequence(insn);
                    if (endNode != null) {
                        removeInstructions(instructions, insn, endNode);
                        modified = true;
                        removed++;
                    }
                }
                
                // Check for useless math operations
                else if (isUselessMathPattern(insn)) {
                    AbstractInsnNode endNode = findEndOfUselessMathSequence(insn);
                    if (endNode != null) {
                        removeInstructions(instructions, insn, endNode);
                        modified = true;
                        removed++;
                    }
                }
                
                insn = next;
            }
        } while (modified);
        
        return removed;
    }
    
    /**
     * Check if this is a push-pop pattern
     */
    private boolean isPushPopPattern(AbstractInsnNode insn) {
        // Push operation (constant, bitvector, etc.)
        if (isPushInstruction(insn)) {
            AbstractInsnNode next = getNextSignificantInstruction(insn);
            return next != null && (next.getOpcode() == POP || next.getOpcode() == POP2);
        }
        return false;
    }
    
    /**
     * Check if this is a string push-pop pattern
     */
    private boolean isStringPushPopPattern(AbstractInsnNode insn) {
        // Check for string load followed by POP
        if (insn instanceof LdcInsnNode && ((LdcInsnNode) insn).cst instanceof String) {
            AbstractInsnNode next = getNextSignificantInstruction(insn);
            return next != null && next.getOpcode() == POP;
        }
        return false;
    }
    
    /**
     * Check if this is a useless math operation
     */
    private boolean isUselessMathPattern(AbstractInsnNode insn) {
        // Check for patterns like:
        // [push val1][push val2][math-op][pop]
        if (isPushInstruction(insn)) {
            AbstractInsnNode next = getNextSignificantInstruction(insn);
            if (next != null && isPushInstruction(next)) {
                AbstractInsnNode operation = getNextSignificantInstruction(next);
                if (operation != null && isMathOperation(operation)) {
                    AbstractInsnNode after = getNextSignificantInstruction(operation);
                    return after != null && (after.getOpcode() == POP || after.getOpcode() == POP2);
                }
            }
        }
        return false;
    }
    
    /**
     * Check if the instruction pushes a value onto the stack
     */
    private boolean isPushInstruction(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        
        // Constants
        if ((opcode >= ICONST_M1 && opcode <= ICONST_5) ||
            (opcode >= LCONST_0 && opcode <= LCONST_1) ||
            (opcode >= FCONST_0 && opcode <= FCONST_2) ||
            (opcode >= DCONST_0 && opcode <= DCONST_1) ||
            opcode == ACONST_NULL) {
            return true;
        }
        
        // Other push instructions
        if (opcode == BIPUSH || opcode == SIPUSH || opcode == LDC) {
            return true;
        }
        
        // NEW operation
        if (opcode == NEW) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if the instruction is a math operation
     */
    private boolean isMathOperation(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        
        // Arithmetic
        if ((opcode >= IADD && opcode <= DREM) ||
            (opcode >= INEG && opcode <= DNEG)) {
            return true;
        }
        
        // Bit operations
        if ((opcode >= ISHL && opcode <= LXOR)) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Find the end of a push-pop sequence
     */
    private AbstractInsnNode findEndOfPushPopSequence(AbstractInsnNode start) {
        AbstractInsnNode current = start;
        
        // Skip push instruction
        current = getNextSignificantInstruction(current);
        
        // Check if it's a POP
        if (current != null && (current.getOpcode() == POP || current.getOpcode() == POP2)) {
            return current;
        }
        
        return null;
    }
    
    /**
     * Find the end of a string push-pop sequence
     */
    private AbstractInsnNode findEndOfStringPushPopSequence(AbstractInsnNode start) {
        AbstractInsnNode current = start;
        
        // Skip LDC
        current = getNextSignificantInstruction(current);
        
        // Check if it's a POP
        if (current != null && current.getOpcode() == POP) {
            return current;
        }
        
        return null;
    }
    
    /**
     * Find the end of a useless math sequence
     */
    private AbstractInsnNode findEndOfUselessMathSequence(AbstractInsnNode start) {
        AbstractInsnNode current = start;
        
        // Skip first push
        current = getNextSignificantInstruction(current);
        if (current == null || !isPushInstruction(current)) return null;
        
        // Skip second push
        current = getNextSignificantInstruction(current);
        if (current == null || !isMathOperation(current)) return null;
        
        // Skip math operation
        current = getNextSignificantInstruction(current);
        
        // Check if it's a POP
        if (current != null && (current.getOpcode() == POP || current.getOpcode() == POP2)) {
            return current;
        }
        
        return null;
    }
    
    /**
     * Get the next significant instruction (skip labels, line numbers, etc.)
     */
    private AbstractInsnNode getNextSignificantInstruction(AbstractInsnNode insn) {
        AbstractInsnNode current = insn.getNext();
        while (current != null && (current instanceof LabelNode || 
                                  current instanceof LineNumberNode || 
                                  current instanceof FrameNode)) {
            current = current.getNext();
        }
        return current;
    }
    
    /**
     * Remove a sequence of instructions from start to end (inclusive)
     */
    private void removeInstructions(InsnList instructions, AbstractInsnNode start, AbstractInsnNode end) {
        AbstractInsnNode current = start;
        while (current != end.getNext()) {
            AbstractInsnNode toRemove = current;
            current = current.getNext();
            instructions.remove(toRemove);
        }
    }
}