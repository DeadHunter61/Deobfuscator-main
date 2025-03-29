package dead.owner.deobf.transformers.skid;

import dead.owner.deobf.Run;
import dead.owner.deobf.utils.wrapper.ClassWrapper;
import dead.owner.deobf.utils.wrapper.MethodWrapper;
import dead.owner.deobf.transformers.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.util.*;

/**
 * Transformer to clean flow obfuscation techniques specific to SkidFuscator.
 * SkidFuscator often adds bogus conditionals, unreachable code, and other
 * flow obfuscation techniques to make code harder to understand.
 */
public class SkidFlowCleaner implements Transformer, Opcodes {

    @Override
    public void transform(ClassWrapper classWrapper) {
        int totalCleaned = 0;

        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            int cleaned = cleanMethod(methodWrapper);
            totalCleaned += cleaned;
        }

        if (totalCleaned > 0) {
            Run.log(classWrapper.getName() + " | Cleaned " + totalCleaned + " flow obfuscations");
        }
    }

    /**
     * Clean flow obfuscations in a method
     */
    private int cleanMethod(MethodWrapper methodWrapper) {
        MethodNode methodNode = methodWrapper.getMethodNode();
        int cleanCount = 0;

        // First pass: Remove bogus conditionals
        cleanCount += cleanBogusConditionals(methodNode);

        // Second pass: Remove unreachable code
        cleanCount += removeUnreachableCode(methodNode);

        // Third pass: Remove opaque predicates
        cleanCount += removeOpaquePredicates(methodNode);

        // Fourth pass: Clean fake loops
        cleanCount += cleanFakeLoops(methodNode);

        return cleanCount;
    }

    /**
     * Clean bogus conditionals - conditions that always evaluate to the same result
     */
    private int cleanBogusConditionals(MethodNode methodNode) {
        int cleaned = 0;

        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Store next before potential modification

            if (insn instanceof JumpInsnNode) {
                JumpInsnNode jumpInsn = (JumpInsnNode) insn;

                // Check for patterns where the condition always evaluates the same way
                AbstractInsnNode prev1 = getPreviousRealInsn(insn);
                AbstractInsnNode prev2 = prev1 != null ? getPreviousRealInsn(prev1) : null;

                if (prev1 != null && prev2 != null) {
                    boolean isAlwaysTrue = false;
                    boolean isAlwaysFalse = false;

                    // Check for constant comparison pattern
                    if (isIntConstant(prev1) && isIntConstant(prev2)) {
                        int value1 = getIntConstantValue(prev1);
                        int value2 = getIntConstantValue(prev2);

                        switch (jumpInsn.getOpcode()) {
                            case IF_ICMPEQ:
                                isAlwaysTrue = (value1 == value2);
                                isAlwaysFalse = (value1 != value2);
                                break;
                            case IF_ICMPNE:
                                isAlwaysTrue = (value1 != value2);
                                isAlwaysFalse = (value1 == value2);
                                break;
                            case IF_ICMPLT:
                                isAlwaysTrue = (value2 < value1);
                                isAlwaysFalse = (value2 >= value1);
                                break;
                            case IF_ICMPGE:
                                isAlwaysTrue = (value2 >= value1);
                                isAlwaysFalse = (value2 < value1);
                                break;
                            case IF_ICMPGT:
                                isAlwaysTrue = (value2 > value1);
                                isAlwaysFalse = (value2 <= value1);
                                break;
                            case IF_ICMPLE:
                                isAlwaysTrue = (value2 <= value1);
                                isAlwaysFalse = (value2 > value1);
                                break;
                        }
                    }

                    // Replace with direct jump or remove jump based on result
                    if (isAlwaysTrue) {
                        // Replace with GOTO
                        methodNode.instructions.insertBefore(insn, new JumpInsnNode(GOTO, jumpInsn.label));
                        methodNode.instructions.remove(insn);
                        methodNode.instructions.remove(prev1);
                        methodNode.instructions.remove(prev2);
                        cleaned++;
                    } else if (isAlwaysFalse) {
                        // Remove the jump completely
                        methodNode.instructions.remove(insn);
                        methodNode.instructions.remove(prev1);
                        methodNode.instructions.remove(prev2);
                        cleaned++;
                    }
                }
            }

            insn = next;
        }

        return cleaned;
    }

    /**
     * Remove code that is unreachable due to unconditional jumps
     */
    private int removeUnreachableCode(MethodNode methodNode) {
        int removed = 0;
        Set<AbstractInsnNode> reachable = new HashSet<>();
        Set<LabelNode> reachableLabels = new HashSet<>();

        // Mark all jump targets as reachable
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof JumpInsnNode) {
                reachableLabels.add(((JumpInsnNode) insn).label);
            } else if (insn instanceof TableSwitchInsnNode) {
                TableSwitchInsnNode switchInsn = (TableSwitchInsnNode) insn;
                reachableLabels.add(switchInsn.dflt);
                for (LabelNode label : switchInsn.labels) {
                    reachableLabels.add(label);
                }
            } else if (insn instanceof LookupSwitchInsnNode) {
                LookupSwitchInsnNode switchInsn = (LookupSwitchInsnNode) insn;
                reachableLabels.add(switchInsn.dflt);
                for (LabelNode label : switchInsn.labels) {
                    reachableLabels.add(label);
                }
            }
        }

        // Mark try-catch blocks as reachable
        if (methodNode.tryCatchBlocks != null) {
            for (TryCatchBlockNode tryCatch : methodNode.tryCatchBlocks) {
                reachableLabels.add(tryCatch.start);
                reachableLabels.add(tryCatch.end);
                reachableLabels.add(tryCatch.handler);
            }
        }

        // Mark the entry point as reachable
        AbstractInsnNode current = methodNode.instructions.getFirst();
        while (current != null) {
            reachable.add(current);

            // If this is an unconditional jump, only follow the jump
            if (current.getOpcode() == GOTO) {
                JumpInsnNode jumpInsn = (JumpInsnNode) current;
                current = jumpInsn.label;
                continue;
            }

            // If this is a return or throw, stop this path
            if ((current.getOpcode() >= IRETURN && current.getOpcode() <= RETURN) ||
                    current.getOpcode() == ATHROW) {
                break;
            }

            // For conditional jumps, mark both paths as reachable
            if (current instanceof JumpInsnNode) {
                JumpInsnNode jumpInsn = (JumpInsnNode) current;
                if (current.getOpcode() != GOTO) {
                    // For conditional jumps, also follow the fall-through path
                    markPathAsReachable(jumpInsn.label, reachable, reachableLabels);
                }
            } else if (current instanceof TableSwitchInsnNode) {
                TableSwitchInsnNode switchInsn = (TableSwitchInsnNode) current;
                markPathAsReachable(switchInsn.dflt, reachable, reachableLabels);
                for (LabelNode label : switchInsn.labels) {
                    markPathAsReachable(label, reachable, reachableLabels);
                }
            } else if (current instanceof LookupSwitchInsnNode) {
                LookupSwitchInsnNode switchInsn = (LookupSwitchInsnNode) current;
                markPathAsReachable(switchInsn.dflt, reachable, reachableLabels);
                for (LabelNode label : switchInsn.labels) {
                    markPathAsReachable(label, reachable, reachableLabels);
                }
            }

            current = current.getNext();
        }

        // Remove unreachable code
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext();

            if (!reachable.contains(insn) && !(insn instanceof LabelNode)) {
                methodNode.instructions.remove(insn);
                removed++;
            }

            insn = next;
        }

        return removed;
    }

    /**
     * Mark a path as reachable
     */
    private void markPathAsReachable(LabelNode start, Set<AbstractInsnNode> reachable, Set<LabelNode> reachableLabels) {
        if (start == null || reachable.contains(start)) {
            return;
        }

        AbstractInsnNode current = start;
        while (current != null) {
            if (reachable.contains(current)) {
                break; // Already visited
            }

            reachable.add(current);

            // If this is an unconditional jump, only follow the jump
            if (current.getOpcode() == GOTO) {
                JumpInsnNode jumpInsn = (JumpInsnNode) current;
                current = jumpInsn.label;
                continue;
            }

            // If this is a return or throw, stop this path
            if ((current.getOpcode() >= IRETURN && current.getOpcode() <= RETURN) ||
                    current.getOpcode() == ATHROW) {
                break;
            }

            // For conditional jumps, mark both paths as reachable
            if (current instanceof JumpInsnNode) {
                JumpInsnNode jumpInsn = (JumpInsnNode) current;
                if (current.getOpcode() != GOTO) {
                    // For conditional jumps, also follow the fall-through path
                    markPathAsReachable(jumpInsn.label, reachable, reachableLabels);
                }
            } else if (current instanceof TableSwitchInsnNode) {
                TableSwitchInsnNode switchInsn = (TableSwitchInsnNode) current;
                markPathAsReachable(switchInsn.dflt, reachable, reachableLabels);
                for (LabelNode label : switchInsn.labels) {
                    markPathAsReachable(label, reachable, reachableLabels);
                }
            } else if (current instanceof LookupSwitchInsnNode) {
                LookupSwitchInsnNode switchInsn = (LookupSwitchInsnNode) current;
                markPathAsReachable(switchInsn.dflt, reachable, reachableLabels);
                for (LabelNode label : switchInsn.labels) {
                    markPathAsReachable(label, reachable, reachableLabels);
                }
            }

            current = current.getNext();
        }
    }

    /**
     * Remove opaque predicates - predicates that always evaluate to a constant
     * but are disguised to look like real conditionals
     */
    private int removeOpaquePredicates(MethodNode methodNode) {
        int removed = 0;

        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Store next before potential modification

            if (insn instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;

                // Check for calls to SkidFuscator's opaque predicate methods
                if (methodInsn.owner.equals("skid/Driver") ||
                        methodInsn.name.equals("get") || methodInsn.name.equals("hash")) {

                    // Look for the conditional jump that follows
                    AbstractInsnNode jumpInsn = findNextJump(methodInsn);
                    if (jumpInsn instanceof JumpInsnNode) {
                        // Replace with a direct jump 
                        methodNode.instructions.insertBefore(jumpInsn,
                                new JumpInsnNode(GOTO, ((JumpInsnNode) jumpInsn).label));

                        // Remove the opaque predicate setup
                        List<AbstractInsnNode> toRemove = new ArrayList<>();
                        AbstractInsnNode current = methodInsn;
                        while (current != jumpInsn) {
                            toRemove.add(current);
                            current = current.getNext();
                        }
                        toRemove.add(jumpInsn);

                        for (AbstractInsnNode remove : toRemove) {
                            methodNode.instructions.remove(remove);
                        }

                        removed++;
                    }
                }
            }

            insn = next;
        }

        return removed;
    }

    /**
     * Clean fake loops - loops that always break/return on first iteration
     */
    private int cleanFakeLoops(MethodNode methodNode) {
        int cleaned = 0;

        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Store next before potential modification

            if (insn instanceof JumpInsnNode && insn.getOpcode() == GOTO) {
                JumpInsnNode gotoInsn = (JumpInsnNode) insn;

                // Check if this is a backward jump (loop)
                if (isBackwardJump(gotoInsn)) {
                    // Look for break conditions that always trigger
                    boolean alwaysBreaks = checkForAlwaysBreakingLoop(methodNode, gotoInsn.label, gotoInsn);

                    if (alwaysBreaks) {
                        // Remove the loop jump
                        methodNode.instructions.remove(gotoInsn);
                        cleaned++;
                    }
                }
            }

            insn = next;
        }

        return cleaned;
    }

    /**
     * Check if a jump is backward (indicating a loop)
     */
    private boolean isBackwardJump(JumpInsnNode jumpInsn) {
        AbstractInsnNode current = jumpInsn;
        while (current != null) {
            if (current == jumpInsn.label) {
                return true; // Jump target is before the jump
            }
            current = current.getPrevious();
        }
        return false;
    }

    /**
     * Check if a loop always breaks on first iteration
     */
    private boolean checkForAlwaysBreakingLoop(MethodNode methodNode, LabelNode loopStart, JumpInsnNode loopEnd) {
        AbstractInsnNode current = loopStart;

        while (current != loopEnd) {
            if (current instanceof JumpInsnNode) {
                JumpInsnNode jumpInsn = (JumpInsnNode) current;
                LabelNode target = jumpInsn.label;

                // Check if this is a forward jump that escapes the loop
                if (isForwardJumpPast(jumpInsn, loopEnd)) {
                    // Check if this break is controlled by an opaque predicate
                    AbstractInsnNode prev = getPreviousRealInsn(jumpInsn);
                    if (prev != null && prev instanceof MethodInsnNode) {
                        MethodInsnNode methodInsn = (MethodInsnNode) prev;
                        if (methodInsn.owner.equals("skid/Driver") ||
                                methodInsn.name.equals("get") || methodInsn.name.equals("hash")) {
                            // This is likely an always-true break condition
                            return true;
                        }
                    }
                }
            }

            // Returns inside the loop effectively break it
            if (current.getOpcode() >= IRETURN && current.getOpcode() <= RETURN) {
                return true;
            }

            current = current.getNext();
            if (current == null) break;
        }

        return false;
    }

    /**
     * Check if a jump goes past a certain instruction
     */
    private boolean isForwardJumpPast(JumpInsnNode jumpInsn, AbstractInsnNode target) {
        AbstractInsnNode current = jumpInsn;
        while (current != null) {
            if (current == target) {
                return false; // We hit the loop end before the jump target
            }
            if (current == jumpInsn.label) {
                return true; // Jump target is after the loop end
            }
            current = current.getNext();
        }
        return true; // Jump goes to the end of the method
    }

    /**
     * Find the next jump instruction
     */
    private AbstractInsnNode findNextJump(AbstractInsnNode start) {
        AbstractInsnNode current = start.getNext();
        while (current != null) {
            if (current instanceof JumpInsnNode) {
                return current;
            }

            // Don't go too far
            if (current.getOpcode() >= IRETURN && current.getOpcode() <= RETURN ||
                    current.getOpcode() == ATHROW) {
                break;
            }

            current = current.getNext();
        }

        return null;
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
     * Get the previous significant instruction
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