package dead.owner.deobf.transformers;

import dead.owner.deobf.Run;
import dead.owner.deobf.utils.BytecodeUtil;
import dead.owner.deobf.utils.wrapper.ClassWrapper;
import dead.owner.deobf.utils.wrapper.MethodWrapper;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

/**
 * Transformer to clean obfuscated constructors, which are critical for Minecraft plugins
 */
public class ConstructorCleaner implements Transformer, Opcodes {
    
    @Override
    public void transform(ClassWrapper classWrapper) {
        int cleaned = 0;
        
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            // Focus on constructors and initialization methods
            if (methodWrapper.isInitializer()) {
                cleaned += cleanConstructor(methodWrapper);
            }
        }
        
        if (cleaned > 0) {
            Run.log(classWrapper.getName() + " | Cleaned " + cleaned + " constructor obfuscations");
        }
    }
    
    /**
     * Clean obfuscated code from a constructor
     * 
     * @return Number of obfuscations removed
     */
    private int cleanConstructor(MethodWrapper methodWrapper) {
        InsnList instructions = methodWrapper.getInstructions();
        int cleaned = 0;
        
        // First, identify the super or this call - everything after that until
        // real code starts might be obfuscation
        AbstractInsnNode constructorCall = findConstructorCall(instructions);
        if (constructorCall == null) {
            return 0;
        }
        
        // Now look for patterns after the constructor call
        AbstractInsnNode current = constructorCall.getNext();
        while (current != null) {
            AbstractInsnNode next = current.getNext();
            
            // Look for obfuscated flow patterns
            if (isObfuscatedConstructorCode(current)) {
                AbstractInsnNode end = findEndOfObfuscatedSequence(current);
                if (end != null) {
                    removeInstructions(instructions, current, end);
                    cleaned++;
                    current = next; // Continue from the next instruction
                    continue;
                }
            }
            
            // Look for encrypted strings or suspicious field/method calls
            if (current instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) current;
                if (isSuspiciousMethodCall(methodInsn)) {
                    // This might be part of the obfuscation - mark it for review
                    // For now we're not deleting it, just identifying suspicious calls
                    Run.log("  Suspicious method call in constructor: " + methodInsn.owner + "." + 
                           methodInsn.name + methodInsn.desc);
                }
            }
            
            current = next;
        }
        
        return cleaned;
    }
    
    /**
     * Find the constructor call (super() or this()) in the method
     */
    private AbstractInsnNode findConstructorCall(InsnList instructions) {
        for (AbstractInsnNode insn : instructions) {
            if (insn instanceof MethodInsnNode methodInsn && 
                methodInsn.getOpcode() == INVOKESPECIAL && 
                methodInsn.name.equals("<init>")) {
                return insn;
            }
        }
        return null;
    }
    
    /**
     * Check if an instruction is likely part of obfuscated constructor code
     */
    private boolean isObfuscatedConstructorCode(AbstractInsnNode insn) {
        // Check for BytecodeUtil's general obfuscated flow detection
        if (BytecodeUtil.isObfuscatedFlow(insn)) {
            return true;
        }
        
        // Special constructor obfuscation patterns
        if (insn instanceof TypeInsnNode typeInsn && typeInsn.getOpcode() == NEW) {
            // Check if this is a Throwable or RuntimeException creation that's never used
            if (typeInsn.desc.equals("java/lang/Throwable") || 
                typeInsn.desc.equals("java/lang/RuntimeException")) {
                
                // Check if it's followed by DUP
                AbstractInsnNode next = BytecodeUtil.getNextRealInsn(insn);
                if (next != null && next.getOpcode() == DUP) {
                    // Likely an obfuscated pattern
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Find the end of an obfuscated code sequence
     */
    private AbstractInsnNode findEndOfObfuscatedSequence(AbstractInsnNode start) {
        AbstractInsnNode current = start;
        
        // For NEW Throwable patterns
        if (current instanceof TypeInsnNode typeInsn && typeInsn.getOpcode() == NEW &&
            (typeInsn.desc.equals("java/lang/Throwable") || typeInsn.desc.equals("java/lang/RuntimeException"))) {
            
            // Find the end of this sequence (usually ends with a POP or a conditional jump)
            while (current != null) {
                if (current.getOpcode() == POP || current.getOpcode() == POP2 ||
                    current instanceof JumpInsnNode) {
                    return current;
                }
                
                // If we hit a new instruction sequence, stop
                if (current != start && (current instanceof TypeInsnNode || 
                                        current.getOpcode() == RETURN || 
                                        current.getOpcode() == ARETURN)) {
                    return current.getPrevious();
                }
                
                current = current.getNext();
            }
        }
        
        // For regular obfuscated flow
        if (BytecodeUtil.isConstantLoad(start)) {
            // Try to find the POP that ends this sequence
            while (current != null) {
                if (current.getOpcode() == POP || current.getOpcode() == POP2) {
                    return current;
                }
                
                // If we hit a new instruction sequence, stop
                if (current != start && (current instanceof TypeInsnNode || 
                                        current.getOpcode() == RETURN || 
                                        current.getOpcode() == ARETURN)) {
                    return current.getPrevious();
                }
                
                current = current.getNext();
            }
        }
        
        return null;
    }
    
    /**
     * Check if a method call is suspicious (potentially part of obfuscation)
     */
    private boolean isSuspiciousMethodCall(MethodInsnNode methodInsn) {
        // Suspicious calls to System.exit or Runtime.exit/halt
        if (methodInsn.owner.equals("java/lang/System") && methodInsn.name.equals("exit")) {
            return true;
        }
        if (methodInsn.owner.equals("java/lang/Runtime") && 
            (methodInsn.name.equals("exit") || methodInsn.name.equals("halt"))) {
            return true;
        }
        
        // Suspicious reflection calls
        if (methodInsn.owner.equals("java/lang/Class") && 
            (methodInsn.name.equals("forName") || methodInsn.name.equals("getDeclaredMethod"))) {
            return true;
        }
        
        // Security manager manipulations
        if (methodInsn.owner.equals("java/lang/System") && 
            (methodInsn.name.equals("setSecurityManager") || methodInsn.name.equals("getSecurityManager"))) {
            return true;
        }
        
        return false;
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