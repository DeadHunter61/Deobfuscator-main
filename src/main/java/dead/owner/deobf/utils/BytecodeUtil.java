package dead.owner.deobf.utils;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.util.Map;

/**
 * Utility class for bytecode analysis and manipulation
 */
public final class BytecodeUtil implements Opcodes {
    
    private static final Map<String, String> BOXING = Map.of(
            "V", "java/lang/Void",
            "Z", "java/lang/Boolean",
            "B", "java/lang/Byte",
            "C", "java/lang/Character",
            "S", "java/lang/Short",
            "I", "java/lang/Integer",
            "F", "java/lang/Float",
            "J", "java/lang/Long",
            "D", "java/lang/Double"
    );
    
    /**
     * Check if the instruction loads a constant onto the stack
     */
    public static boolean isConstantLoad(AbstractInsnNode insn) {
        if (insn == null) return false;
        
        int opcode = insn.getOpcode();
        return isInteger(insn) || isLong(insn) || isFloat(insn) || 
               isDouble(insn) || opcode == ACONST_NULL;
    }
    
    /**
     * Check if the instruction is a push instruction for an integer constant
     */
    public static boolean isInteger(AbstractInsnNode insn) {
        if (insn == null) return false;
        int opcode = insn.getOpcode();
        return ((opcode >= ICONST_M1 && opcode <= ICONST_5)
                || opcode == BIPUSH
                || opcode == SIPUSH
                || (insn instanceof LdcInsnNode ldcInsnNode
                && ldcInsnNode.cst instanceof Integer));
    }
    
    /**
     * Check if the instruction is a push instruction for a long constant
     */
    public static boolean isLong(AbstractInsnNode insn) {
        if (insn == null) return false;
        int opcode = insn.getOpcode();
        return (opcode == LCONST_0
                || opcode == LCONST_1
                || (insn instanceof LdcInsnNode ldcInsnNode
                && ldcInsnNode.cst instanceof Long));
    }
    
    /**
     * Check if the instruction is a push instruction for a float constant
     */
    public static boolean isFloat(AbstractInsnNode insn) {
        if (insn == null) return false;
        int opcode = insn.getOpcode();
        return (opcode >= FCONST_0 && opcode <= FCONST_2)
                || (insn instanceof LdcInsnNode ldcInsnNode 
                && ldcInsnNode.cst instanceof Float);
    }
    
    /**
     * Check if the instruction is a push instruction for a double constant
     */
    public static boolean isDouble(AbstractInsnNode insn) {
        if (insn == null) return false;
        int opcode = insn.getOpcode();
        return (opcode >= DCONST_0 && opcode <= DCONST_1)
                || (insn instanceof LdcInsnNode ldcInsnNode 
                && ldcInsnNode.cst instanceof Double);
    }
    
    /**
     * Check if the instruction is a push instruction for a string constant
     */
    public static boolean isString(AbstractInsnNode insn) {
        if (insn == null) return false;
        return (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String);
    }
    
    /**
     * Get the string value from an LDC instruction
     */
    public static String getString(AbstractInsnNode insn) {
        if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String str) 
            return str;
        throw new IllegalArgumentException("Not a string instruction");
    }
    
    /**
     * Check if the instruction is a method invocation
     */
    public static boolean isInvoke(AbstractInsnNode node) {
        int opcode = node.getOpcode();
        return (opcode >= INVOKEVIRTUAL && opcode <= INVOKEINTERFACE);
    }
    
    /**
     * Check if the instruction is a static method invocation
     */
    public static boolean isStaticInvoke(AbstractInsnNode node) {
        return (node.getOpcode() == INVOKESTATIC);
    }
    
    /**
     * Check if the instruction is a field access
     */
    public static boolean isField(AbstractInsnNode node) {
        int opcode = node.getOpcode();
        return (opcode >= GETSTATIC && opcode <= PUTFIELD);
    }
    
    /**
     * Check if the instruction is a static field access
     */
    public static boolean isStaticField(AbstractInsnNode node) {
        int opcode = node.getOpcode();
        return (opcode >= GETSTATIC && opcode <= PUTSTATIC);
    }
    
    /**
     * Get the next instruction, skipping labels, line numbers, and frames
     */
    public static AbstractInsnNode getNextRealInsn(AbstractInsnNode insn) {
        AbstractInsnNode next = insn.getNext();
        while (next != null && (next instanceof LabelNode || 
                               next instanceof LineNumberNode || 
                               next instanceof FrameNode)) {
            next = next.getNext();
        }
        return next;
    }
    
    /**
     * Get the previous instruction, skipping labels, line numbers, and frames
     */
    public static AbstractInsnNode getPrevRealInsn(AbstractInsnNode insn) {
        AbstractInsnNode prev = insn.getPrevious();
        while (prev != null && (prev instanceof LabelNode || 
                               prev instanceof LineNumberNode || 
                               prev instanceof FrameNode)) {
            prev = prev.getPrevious();
        }
        return prev;
    }
    
    /**
     * Check if a method descriptor matches a common pattern for encrypted string methods
     */
    public static boolean isStringDecryptorDescriptor(String desc) {
        return desc.equals("([BLjava/lang/StackTraceElement;)[B") ||
               desc.equals("(Ljava/lang/String;)[B") ||
               desc.equals("(Ljava/lang/String;)Ljava/lang/String;") ||
               desc.equals("([B)[B");
    }
    
    /**
     * Get the box type for a primitive type
     */
    public static String getBoxedType(String desc) {
        Type type = Type.getType(desc);
        if (!BOXING.containsKey(type.getDescriptor()))
            return desc;
        return Type.getType("L" + BOXING.get(type.getDescriptor()) + ";").getDescriptor();
    }
    
    /**
     * Check if an instruction is likely part of obfuscated flow control
     */
    public static boolean isObfuscatedFlow(AbstractInsnNode insn) {
        // Check for pattern: push constant(s) -> perform operation -> pop
        if (isConstantLoad(insn)) {
            AbstractInsnNode next = getNextRealInsn(insn);
            
            if (next != null && isConstantLoad(next)) {
                // Two constants in a row - might be an obfuscated operation
                AbstractInsnNode op = getNextRealInsn(next);
                if (op != null && isMathOperation(op)) {
                    AbstractInsnNode after = getNextRealInsn(op);
                    return after != null && (after.getOpcode() == POP || after.getOpcode() == POP2);
                }
            } else if (next != null && next.getOpcode() == POP) {
                // Single constant followed by POP - definitely dead code
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Check if an instruction is a mathematical operation
     */
    public static boolean isMathOperation(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        return (opcode >= IADD && opcode <= DREM) || // Arithmetic operations
               (opcode >= ISHL && opcode <= LXOR);   // Bitwise operations
    }
}