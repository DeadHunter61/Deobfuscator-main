package dead.owner.deobf.transformers;

import dead.owner.deobf.Run;
import dead.owner.deobf.utils.wrapper.ClassWrapper;
import dead.owner.deobf.utils.wrapper.MethodWrapper;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.util.*;

/**
 * Transformer to simplify and clean up obfuscated try-catch blocks
 */
public class TryCatchSimplifier implements Transformer, Opcodes {

    @Override
    public void transform(ClassWrapper classWrapper) {
        int removedTryCatch = 0;
        int simplifiedTryCatch = 0;
        
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            MethodNode methodNode = methodWrapper.getMethodNode();
            
            if (methodNode.tryCatchBlocks == null || methodNode.tryCatchBlocks.isEmpty()) {
                continue;
            }
            
            // Identify and remove obfuscated try-catch blocks
            removedTryCatch += removeObfuscatedTryCatchBlocks(methodNode);
            
            // Simplify try-catch blocks that switch control flow with RuntimeException/IllegalAccessException
            simplifiedTryCatch += simplifyControlFlowTryCatchBlocks(methodNode);
            
            // Clean up code inside try-catch blocks
            cleanupTryCatchCodeBlocks(methodNode);
        }
        
        if (removedTryCatch > 0 || simplifiedTryCatch > 0) {
            Run.log(classWrapper.getName() + " | Removed " + removedTryCatch + 
                   " obfuscated try-catch blocks and simplified " + simplifiedTryCatch + " control flow blocks");
        }
    }
    
    /**
     * Remove try-catch blocks that are only used for obfuscation
     */
    private int removeObfuscatedTryCatchBlocks(MethodNode methodNode) {
        if (methodNode.tryCatchBlocks == null) {
            return 0;
        }
        
        int removed = 0;
        Iterator<TryCatchBlockNode> iterator = methodNode.tryCatchBlocks.iterator();
        
        while (iterator.hasNext()) {
            TryCatchBlockNode tryCatchBlock = iterator.next();
            
            // Check if this is an obfuscated try-catch block
            if (isObfuscatedTryCatch(methodNode, tryCatchBlock)) {
                iterator.remove();
                removed++;
                
                // Remove the throw instruction if it's there just for obfuscation
                AbstractInsnNode insn = findThrowInsn(methodNode, tryCatchBlock);
                if (insn != null && isPurelyObfuscatedThrow(methodNode, insn)) {
                    methodNode.instructions.remove(insn);
                }
            }
        }
        
        return removed;
    }
    
    /**
     * Simplify try-catch blocks that are used for control flow
     */
    private int simplifyControlFlowTryCatchBlocks(MethodNode methodNode) {
        if (methodNode.tryCatchBlocks == null) {
            return 0;
        }
        
        int simplified = 0;
        Map<LabelNode, LabelNode> labelMap = new HashMap<>();
        
        // First identify the control flow try-catch blocks
        for (TryCatchBlockNode tryCatchBlock : methodNode.tryCatchBlocks) {
            if (isControlFlowTryCatch(methodNode, tryCatchBlock)) {
                // Find the throw instruction in the try block
                AbstractInsnNode throwInsn = findIntentionalThrow(methodNode, tryCatchBlock.start, tryCatchBlock.end);
                if (throwInsn != null) {
                    // Find the handler code - typically has a hash check
                    AbstractInsnNode handlerInsn = findFirstInsnAfterLabel(methodNode, tryCatchBlock.handler);
                    if (handlerInsn != null) {
                        // Map the handler label to a direct branch target
                        LabelNode targetLabel = findDirectJumpTarget(methodNode, handlerInsn);
                        if (targetLabel != null) {
                            labelMap.put(tryCatchBlock.handler, targetLabel);
                            simplified++;
                        }
                    }
                }
            }
        }
        
        // Now replace the try-catch handlers with direct jumps
        if (!labelMap.isEmpty()) {
            // First add direct jumps
            for (Map.Entry<LabelNode, LabelNode> entry : labelMap.entrySet()) {
                LabelNode handlerLabel = entry.getKey();
                LabelNode targetLabel = entry.getValue();
                
                // Add a GOTO to the target right after the handler label
                JumpInsnNode gotoInsn = new JumpInsnNode(GOTO, targetLabel);
                methodNode.instructions.insert(handlerLabel, gotoInsn);
            }
            
            // Then remove the try-catch blocks
            Iterator<TryCatchBlockNode> iterator = methodNode.tryCatchBlocks.iterator();
            while (iterator.hasNext()) {
                TryCatchBlockNode tryCatchBlock = iterator.next();
                if (labelMap.containsKey(tryCatchBlock.handler)) {
                    iterator.remove();
                }
            }
        }
        
        return simplified;
    }
    
    /**
     * Clean up code inside try-catch blocks
     */
    private void cleanupTryCatchCodeBlocks(MethodNode methodNode) {
        if (methodNode.tryCatchBlocks == null || methodNode.tryCatchBlocks.isEmpty()) {
            return;
        }
        
        // For each try-catch block, examine the code inside to remove obfuscation
        for (TryCatchBlockNode tryCatchBlock : methodNode.tryCatchBlocks) {
            // Clean up the try block
            cleanupTryBlock(methodNode, tryCatchBlock.start, tryCatchBlock.end);
            
            // Clean up the handler block
            cleanupHandlerBlock(methodNode, tryCatchBlock.handler);
        }
    }
    
    /**
     * Clean up code inside a try block
     */
    private void cleanupTryBlock(MethodNode methodNode, LabelNode start, LabelNode end) {
        AbstractInsnNode current = start;
        while (current != end) {
            AbstractInsnNode next = current.getNext();
            
            // Look for obfuscated patterns inside try blocks
            if (current instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) current;
                if (methodInsn.name.equals("nudzrwhrluemgkta") || 
                    methodInsn.name.equals("xhrwevfwjdjhyfeh") ||
                    methodInsn.name.equals("ttsgbhaeitkbgppm")) {
                    
                    // These are usually part of the obfuscation - try to remove them
                    removeObfuscatedMethodCall(methodNode, methodInsn);
                }
            }
            
            current = next;
        }
    }
    
    /**
     * Clean up code inside a catch handler
     */
    private void cleanupHandlerBlock(MethodNode methodNode, LabelNode handler) {
        // For each handler, look for patterns like:
        // handler:
        //   astore X
        //   ... switch based on some hash ...
        
        AbstractInsnNode current = handler.getNext();
        
        // Skip past the exception store
        if (current != null && current.getOpcode() == ASTORE) {
            current = current.getNext();
        }
        
        // Look for hash-based control flow
        while (current != null) {
            // If we hit a GOTO, RETURN, or ATHROW, we've reached the end of this handler
            if (current.getOpcode() == GOTO || 
                (current.getOpcode() >= IRETURN && current.getOpcode() <= RETURN) || 
                current.getOpcode() == ATHROW) {
                break;
            }
            
            // Check for hash calculation for control flow
            if (current instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) current;
                if (methodInsn.name.equals("ttsgbhaeitkbgppm")) {
                    // This is a hash check - try to find the switch that follows
                    AbstractInsnNode switchInsn = findNextSwitch(current);
                    if (switchInsn != null) {
                        // If this is part of obfuscated control flow, try to simplify it
                        replaceObfuscatedSwitchWithGoto(methodNode, current, switchInsn);
                    }
                }
            }
            
            current = current.getNext();
        }
    }
    
    /**
     * Check if a try-catch block is used purely for obfuscation
     */
    private boolean isObfuscatedTryCatch(MethodNode methodNode, TryCatchBlockNode tryCatchBlock) {
        // Check if the try block is empty or just contains a throw
        AbstractInsnNode current = tryCatchBlock.start.getNext();
        boolean hasOnlyThrow = false;
        boolean hasRealCode = false;
        
        while (current != tryCatchBlock.end) {
            if (current instanceof LabelNode || current instanceof LineNumberNode || current instanceof FrameNode) {
                current = current.getNext();
                continue;
            }
            
            if (current.getOpcode() == ATHROW) {
                hasOnlyThrow = true;
            } else if (current.getOpcode() != NOP) {
                hasRealCode = true;
            }
            
            current = current.getNext();
        }
        
        // Case 1: Empty try block with a catch for RuntimeException/IllegalAccessException
        if (!hasRealCode && !hasOnlyThrow && 
            (tryCatchBlock.type == null || 
             tryCatchBlock.type.equals("java/lang/RuntimeException") || 
             tryCatchBlock.type.equals("java/lang/IllegalAccessException"))) {
            return true;
        }
        
        // Case 2: Try block with just a throw and a catch that never re-throws
        if (hasOnlyThrow && !hasRealCode && !doesHandlerRethrow(methodNode, tryCatchBlock.handler)) {
            return true;
        }
        
        // Case 3: Handler doesn't use the exception at all
        if (doesHandlerIgnoreException(methodNode, tryCatchBlock.handler)) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if a try-catch block is used for control flow
     */
    private boolean isControlFlowTryCatch(MethodNode methodNode, TryCatchBlockNode tryCatchBlock) {
        // Check if the try block contains an intentional throw
        AbstractInsnNode throwInsn = findIntentionalThrow(methodNode, tryCatchBlock.start, tryCatchBlock.end);
        if (throwInsn == null) {
            return false;
        }
        
        // Check if the handler contains a hash check for control flow
        AbstractInsnNode current = tryCatchBlock.handler.getNext();
        
        // Skip past the exception store
        if (current != null && current.getOpcode() == ASTORE) {
            current = current.getNext();
        }
        
        while (current != null) {
            // Look for hash-based control flow
            if (current instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) current;
                if (methodInsn.name.equals("ttsgbhaeitkbgppm")) {
                    return true;
                }
            }
            
            // If we hit a GOTO, RETURN, or ATHROW, we've reached the end of this handler
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
     * Find an intentional throw instruction in a code block
     */
    private AbstractInsnNode findIntentionalThrow(MethodNode methodNode, LabelNode start, LabelNode end) {
        AbstractInsnNode current = start.getNext();
        
        while (current != end) {
            // Look for patterns like:
            // new IllegalAccessException/RuntimeException
            // dup
            // invokespecial <init>
            // athrow
            
            if (current instanceof TypeInsnNode && current.getOpcode() == NEW) {
                TypeInsnNode typeInsn = (TypeInsnNode) current;
                if (typeInsn.desc.equals("java/lang/IllegalAccessException") || 
                    typeInsn.desc.equals("java/lang/RuntimeException")) {
                    
                    // Check if it's followed by dup, init, throw
                    AbstractInsnNode next1 = getNextRealInsn(current);
                    AbstractInsnNode next2 = next1 != null ? getNextRealInsn(next1) : null;
                    AbstractInsnNode next3 = next2 != null ? getNextRealInsn(next2) : null;
                    
                    if (next1 != null && next1.getOpcode() == DUP && 
                        next2 instanceof MethodInsnNode && ((MethodInsnNode)next2).name.equals("<init>") &&
                        next3 != null && next3.getOpcode() == ATHROW) {
                        return current;
                    }
                }
            } else if (current.getOpcode() == ATHROW) {
                // Check if this throw is preceded by code to generate a throwable
                AbstractInsnNode prev = getPreviousRealInsn(current);
                if (prev instanceof MethodInsnNode && ((MethodInsnNode)prev).name.equals("<init>")) {
                    return current;
                }
            }
            
            current = current.getNext();
        }
        
        return null;
    }
    
    /**
     * Find a throw instruction in a try block
     */
    private AbstractInsnNode findThrowInsn(MethodNode methodNode, TryCatchBlockNode tryCatchBlock) {
        AbstractInsnNode current = tryCatchBlock.start.getNext();
        
        while (current != tryCatchBlock.end) {
            if (current.getOpcode() == ATHROW) {
                return current;
            }
            current = current.getNext();
        }
        
        return null;
    }
    
    /**
     * Check if a throw instruction is purely for obfuscation
     */
    private boolean isPurelyObfuscatedThrow(MethodNode methodNode, AbstractInsnNode throwInsn) {
        if (throwInsn.getOpcode() != ATHROW) {
            return false;
        }
        
        // Check if this throw is preceded by creating a new exception
        AbstractInsnNode prev1 = getPreviousRealInsn(throwInsn);
        if (prev1 instanceof MethodInsnNode && ((MethodInsnNode)prev1).name.equals("<init>")) {
            AbstractInsnNode prev2 = getPreviousRealInsn(prev1);
            if (prev2 != null && prev2.getOpcode() == DUP) {
                AbstractInsnNode prev3 = getPreviousRealInsn(prev2);
                if (prev3 instanceof TypeInsnNode && prev3.getOpcode() == NEW) {
                    TypeInsnNode typeInsn = (TypeInsnNode) prev3;
                    return typeInsn.desc.equals("java/lang/RuntimeException") || 
                          typeInsn.desc.equals("java/lang/IllegalAccessException");
                }
            }
        }
        
        return false;
    }
    
    /**
     * Check if an exception handler doesn't actually use the exception
     */
    private boolean doesHandlerIgnoreException(MethodNode methodNode, LabelNode handler) {
        AbstractInsnNode current = handler.getNext();
        
        // Check if the exception is stored
        if (current != null && current.getOpcode() == ASTORE) {
            int varIndex = ((VarInsnNode) current).var;
            
            // Check if the variable is ever loaded
            current = current.getNext();
            while (current != null) {
                if (current instanceof VarInsnNode && 
                    current.getOpcode() == ALOAD && 
                    ((VarInsnNode) current).var == varIndex) {
                    return false;
                }
                
                // If we hit a GOTO, RETURN, or ATHROW, we've reached the end of this handler
                if (current.getOpcode() == GOTO || 
                    (current.getOpcode() >= IRETURN && current.getOpcode() <= RETURN) || 
                    current.getOpcode() == ATHROW) {
                    break;
                }
                
                current = current.getNext();
            }
            
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if an exception handler re-throws the exception
     */
    private boolean doesHandlerRethrow(MethodNode methodNode, LabelNode handler) {
        AbstractInsnNode current = handler.getNext();
        
        // Check if the exception is stored
        if (current != null && current.getOpcode() == ASTORE) {
            int varIndex = ((VarInsnNode) current).var;
            
            // Check if the variable is loaded and immediately thrown
            current = current.getNext();
            while (current != null) {
                if (current instanceof VarInsnNode && 
                    current.getOpcode() == ALOAD && 
                    ((VarInsnNode) current).var == varIndex) {
                    
                    AbstractInsnNode next = getNextRealInsn(current);
                    if (next != null && next.getOpcode() == ATHROW) {
                        return true;
                    }
                }
                
                // If we hit a GOTO, RETURN, or another ATHROW, we've reached the end of this handler
                if (current.getOpcode() == GOTO || 
                    (current.getOpcode() >= IRETURN && current.getOpcode() <= RETURN) || 
                    current.getOpcode() == ATHROW) {
                    break;
                }
                
                current = current.getNext();
            }
        }
        
        return false;
    }
    
    /**
     * Find the first instruction after a label
     */
    private AbstractInsnNode findFirstInsnAfterLabel(MethodNode methodNode, LabelNode label) {
        AbstractInsnNode current = label.getNext();
        
        while (current != null && (current instanceof LabelNode || 
                                  current instanceof LineNumberNode || 
                                  current instanceof FrameNode)) {
            current = current.getNext();
        }
        
        return current;
    }
    
    /**
     * Find the target of a direct jump
     */
    private LabelNode findDirectJumpTarget(MethodNode methodNode, AbstractInsnNode start) {
        AbstractInsnNode current = start;
        
        // Look for a direct GOTO within a reasonable distance
        int distance = 0;
        while (current != null && distance < 20) {
            if (current instanceof JumpInsnNode && current.getOpcode() == GOTO) {
                return ((JumpInsnNode) current).label;
            }
            
            current = current.getNext();
            distance++;
        }
        
        return null;
    }
    
    /**
     * Remove an obfuscated method call and associated instructions
     */
    private void removeObfuscatedMethodCall(MethodNode methodNode, MethodInsnNode methodInsn) {
        // First find the argument pushes
        List<AbstractInsnNode> toRemove = new ArrayList<>();
        toRemove.add(methodInsn);
        
        // Find the previous push instruction(s)
        AbstractInsnNode current = methodInsn.getPrevious();
        while (current != null && isPushInstruction(current)) {
            toRemove.add(current);
            current = current.getPrevious();
        }
        
        // Find any following control flow that depends on this call
        current = methodInsn.getNext();
        while (current != null && 
              (current instanceof JumpInsnNode || current.getOpcode() == IFEQ || 
               current.getOpcode() == IFNE || current.getOpcode() == TABLESWITCH || 
               current.getOpcode() == LOOKUPSWITCH)) {
            toRemove.add(current);
            current = current.getNext();
        }
        
        // Remove all identified instructions
        for (AbstractInsnNode insn : toRemove) {
            methodNode.instructions.remove(insn);
        }
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
     * Replace an obfuscated switch with a direct GOTO
     */
    private void replaceObfuscatedSwitchWithGoto(MethodNode methodNode, AbstractInsnNode start, AbstractInsnNode switchInsn) {
        // For simplicity, we'll just replace the entire sequence with a GOTO to the first target
        LabelNode targetLabel = null;
        
        if (switchInsn instanceof TableSwitchInsnNode) {
            TableSwitchInsnNode tableSwitchNode = (TableSwitchInsnNode) switchInsn;
            targetLabel = !tableSwitchNode.labels.isEmpty() ? tableSwitchNode.labels.get(0) : tableSwitchNode.dflt;
        } else if (switchInsn instanceof LookupSwitchInsnNode) {
            LookupSwitchInsnNode lookupSwitchNode = (LookupSwitchInsnNode) switchInsn;
            targetLabel = !lookupSwitchNode.labels.isEmpty() ? lookupSwitchNode.labels.get(0) : lookupSwitchNode.dflt;
        }
        
        if (targetLabel != null) {
            // Remove all instructions between start and switchInsn (inclusive)
            AbstractInsnNode current = start;
            while (current != switchInsn.getNext()) {
                AbstractInsnNode toRemove = current;
                current = current.getNext();
                methodNode.instructions.remove(toRemove);
            }
            
            // Add a GOTO to the target
            JumpInsnNode gotoInsn = new JumpInsnNode(GOTO, targetLabel);
            methodNode.instructions.insertBefore(current, gotoInsn);
        }
    }
    
    /**
     * Check if an instruction pushes a value onto the stack
     */
    private boolean isPushInstruction(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        
        return (opcode >= ICONST_M1 && opcode <= ICONST_5) ||
               (opcode >= LCONST_0 && opcode <= LCONST_1) ||
               (opcode >= FCONST_0 && opcode <= FCONST_2) ||
               (opcode >= DCONST_0 && opcode <= DCONST_1) ||
               opcode == BIPUSH || 
               opcode == SIPUSH || 
               opcode == LDC ||
               (opcode >= ILOAD && opcode <= ALOAD);
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