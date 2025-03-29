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
 * Transformer to unmask numbers obfuscated by SkidFuscator.
 * SkidFuscator uses several techniques to obfuscate numeric constants:
 * 1. XOR operations (NumberTransformer)
 * 2. Negation and double negation (NegationTransformer)
 * 3. Complex arithmetic expressions
 */
public class SkidNumberUnmasker implements Transformer, Opcodes {

    // Types to consider for unmasking
    private static final Set<Type> NUMBER_TYPES = new HashSet<>(Arrays.asList(
            Type.INT_TYPE,
            Type.SHORT_TYPE,
            Type.BYTE_TYPE,
            Type.CHAR_TYPE,
            Type.LONG_TYPE,
            Type.FLOAT_TYPE,
            Type.DOUBLE_TYPE
    ));

    @Override
    public void transform(ClassWrapper classWrapper) {
        int totalUnmasked = 0;

        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            int unmasked = unmaskNumbers(methodWrapper);
            totalUnmasked += unmasked;
        }

        if (totalUnmasked > 0) {
            Run.log(classWrapper.getName() + " | Unmasked " + totalUnmasked + " obfuscated numbers");
        }
    }

    /**
     * Unmask obfuscated numbers in a method
     */
    private int unmaskNumbers(MethodWrapper methodWrapper) {
        MethodNode methodNode = methodWrapper.getMethodNode();
        int unmasked = 0;

        // First pass: simplify negation operations
        unmasked += simplifyNegations(methodNode);

        // Second pass: simplify XOR operations
        unmasked += simplifyXorOperations(methodNode);

        // Third pass: simplify arithmetic operations
        unmasked += simplifyArithmeticOperations(methodNode);

        return unmasked;
    }

    /**
     * Simplify negation operations (INEG, LNEG, etc.)
     */
    private int simplifyNegations(MethodNode methodNode) {
        int simplified = 0;

        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Store next before potential modification

            if (insn.getOpcode() == INEG) {
                // Look for negation of a constant
                AbstractInsnNode prev = getPreviousRealInsn(insn);
                if (prev != null && isIntConstant(prev)) {
                    int value = getIntConstantValue(prev);
                    value = -value; // Negate the value

                    // Replace with direct constant
                    AbstractInsnNode newInsn;
                    if (value >= -1 && value <= 5) {
                        newInsn = new InsnNode(ICONST_0 + value);
                    } else if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) {
                        newInsn = new IntInsnNode(BIPUSH, value);
                    } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
                        newInsn = new IntInsnNode(SIPUSH, value);
                    } else {
                        newInsn = new LdcInsnNode(value);
                    }

                    methodNode.instructions.insertBefore(prev, newInsn);
                    methodNode.instructions.remove(prev);
                    methodNode.instructions.remove(insn);
                    simplified++;
                    next = newInsn.getNext();
                }
            } else if (insn.getOpcode() == INEG) {
                // Look for double negation pattern (INEG, INEG)
                AbstractInsnNode prev = getPreviousRealInsn(insn);
                if (prev != null && prev.getOpcode() == INEG) {
                    // Double negation cancels out - remove both INEG instructions
                    methodNode.instructions.remove(prev);
                    methodNode.instructions.remove(insn);
                    simplified++;
                }
            }

            // Handle other negation types (LNEG, FNEG, DNEG) similarly
            // For brevity, only showing INEG case here

            insn = next;
        }

        return simplified;
    }

    /**
     * Simplify XOR operations
     */
    private int simplifyXorOperations(MethodNode methodNode) {
        int simplified = 0;

        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Store next before potential modification

            if (insn.getOpcode() == IXOR) {
                // Look for XOR with a constant
                AbstractInsnNode prev1 = getPreviousRealInsn(insn);
                AbstractInsnNode prev2 = prev1 != null ? getPreviousRealInsn(prev1) : null;

                if (prev1 != null && prev2 != null &&
                        isIntConstant(prev1) && isIntConstant(prev2)) {

                    int value1 = getIntConstantValue(prev1);
                    int value2 = getIntConstantValue(prev2);
                    int result = value1 ^ value2;

                    // Replace with direct constant
                    AbstractInsnNode newInsn = createIntConstant(result);
                    methodNode.instructions.insertBefore(prev2, newInsn);
                    methodNode.instructions.remove(prev2);
                    methodNode.instructions.remove(prev1);
                    methodNode.instructions.remove(insn);
                    simplified++;
                    next = newInsn.getNext();
                }
            }

            // Handle LXOR similarly
            // For brevity, only showing IXOR case here

            insn = next;
        }

        return simplified;
    }

    /**
     * Simplify arithmetic operations (ADD, SUB, MUL, DIV, REM)
     */
    private int simplifyArithmeticOperations(MethodNode methodNode) {
        int simplified = 0;

        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Store next before potential modification

            int opcode = insn.getOpcode();
            if ((opcode >= IADD && opcode <= DREM) && opcode != INEG && opcode != LNEG &&
                    opcode != FNEG && opcode != DNEG) {

                // Look for arithmetic operation with two constants
                AbstractInsnNode prev1 = getPreviousRealInsn(insn);
                AbstractInsnNode prev2 = prev1 != null ? getPreviousRealInsn(prev1) : null;

                if (prev1 != null && prev2 != null && isIntConstant(prev1) && isIntConstant(prev2)) {
                    int value1 = getIntConstantValue(prev1);
                    int value2 = getIntConstantValue(prev2);
                    int result = 0;

                    // Calculate the result based on the operation
                    switch (opcode) {
                        case IADD:
                            result = value1 + value2;
                            break;
                        case ISUB:
                            result = value2 - value1; // Note the order
                            break;
                        case IMUL:
                            result = value1 * value2;
                            break;
                        case IDIV:
                            if (value1 != 0) result = value2 / value1; // Avoid division by zero
                            else continue;
                            break;
                        case IREM:
                            if (value1 != 0) result = value2 % value1; // Avoid division by zero
                            else continue;
                            break;
                        case ISHL:
                            result = value2 << value1;
                            break;
                        case ISHR:
                            result = value2 >> value1;
                            break;
                        case IUSHR:
                            result = value2 >>> value1;
                            break;
                        case IAND:
                            result = value1 & value2;
                            break;
                        case IOR:
                            result = value1 | value2;
                            break;
                        // Handle other operations similarly
                        default:
                            continue; // Skip if not handled
                    }

                    // Replace with direct constant
                    AbstractInsnNode newInsn = createIntConstant(result);
                    methodNode.instructions.insertBefore(prev2, newInsn);
                    methodNode.instructions.remove(prev2);
                    methodNode.instructions.remove(prev1);
                    methodNode.instructions.remove(insn);
                    simplified++;
                    next = newInsn.getNext();
                }
            }

            insn = next;
        }

        return simplified;
    }

    /**
     * Check if an instruction is an integer constant
     */
    private boolean isIntConstant(AbstractInsnNode insn) {
        return insn.getOpcode() >= ICONST_M1 && insn.getOpcode() <= ICONST_5 ||
                insn.getOpcode() == BIPUSH ||
                insn.getOpcode() == SIPUSH ||
                (insn instanceof LdcInsnNode && ((LdcInsnNode) insn).cst instanceof Integer);
    }

    /**
     * Get the integer value from a constant instruction
     */
    private int getIntConstantValue(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();

        if (opcode >= ICONST_M1 && opcode <= ICONST_5) {
            return opcode - ICONST_0;
        } else if (insn.getOpcode() == BIPUSH || insn.getOpcode() == SIPUSH) {
            return ((IntInsnNode) insn).operand;
        } else if (insn instanceof LdcInsnNode && ((LdcInsnNode) insn).cst instanceof Integer) {
            return (Integer) ((LdcInsnNode) insn).cst;
        }

        throw new IllegalArgumentException("Not an integer constant: " + insn.getOpcode());
    }

    /**
     * Create an integer constant instruction
     */
    private AbstractInsnNode createIntConstant(int value) {
        if (value >= -1 && value <= 5) {
            return new InsnNode(ICONST_M1 + value + 1);  // Adjusted for ICONST_M1
        } else if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) {
            return new IntInsnNode(BIPUSH, value);
        } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
            return new IntInsnNode(SIPUSH, value);
        } else {
            return new LdcInsnNode(value);
        }
    }

    /**
     * Get the previous significant instruction (skip labels, etc.)
     */
    private AbstractInsnNode getPreviousRealInsn(AbstractInsnNode insn) {
        AbstractInsnNode prev = insn.getPrevious();
        while (prev != null && (prev instanceof LabelNode ||
                prev instanceof LineNumberNode ||
                prev instanceof FrameNode)) {
            prev = prev.getPrevious();
        }
        return prev;
    }
}