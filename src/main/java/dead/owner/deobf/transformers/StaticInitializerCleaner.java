package dead.owner.deobf.transformers;

import dead.owner.deobf.Run;
import dead.owner.deobf.utils.wrapper.ClassWrapper;
import dead.owner.deobf.utils.wrapper.MethodWrapper;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.util.*;

/**
 * Transformer to clean up static initializer blocks
 */
public class StaticInitializerCleaner implements Transformer, Opcodes {
    
    @Override
    public void transform(ClassWrapper classWrapper) {
        MethodWrapper clinitMethod = classWrapper.findMethod("<clinit>", "()V");
        if (clinitMethod == null) {
            return;
        }
        
        MethodNode methodNode = clinitMethod.getMethodNode();
        
        // Remove ASCII art initializations
        boolean removedAsciiArt = removeAsciiArtInitialization(classWrapper, methodNode);
        
        // Remove ByteBuffer.wrap transformations
        boolean removedByteBuffer = removeByteBufferWrapTransformations(methodNode);
        
        // Remove random number initializations
        boolean removedRandom = removeRandomNumberInitializations(methodNode);
        
        // If there's nothing left in the clinit, remove it entirely
        if (isClinitEmpty(methodNode)) {
            classWrapper.getMethodsAsNodes().remove(methodNode);
            Run.log(classWrapper.getName() + " | Removed empty <clinit> method");
        } else if (removedAsciiArt || removedByteBuffer || removedRandom) {
            Run.log(classWrapper.getName() + " | Cleaned up <clinit> method");
        }
    }
    
    /**
     * Remove ASCII art initializations from the static initializer
     */
    private boolean removeAsciiArtInitialization(ClassWrapper classWrapper, MethodNode methodNode) {
        boolean modified = false;
        
        // Look for array stores to nothing_to_see_here field
        for (FieldNode fieldNode : classWrapper.getFieldsAsNodes()) {
            if (fieldNode.name.equals("nothing_to_see_here") && 
                fieldNode.desc.equals("[Ljava/lang/String;")) {
                
                List<AbstractInsnNode> insnsToRemove = new ArrayList<>();
                
                // Find array initialization
                for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn instanceof FieldInsnNode) {
                        FieldInsnNode fieldInsn = (FieldInsnNode) insn;
                        if (fieldInsn.getOpcode() == PUTSTATIC && 
                            fieldInsn.name.equals("nothing_to_see_here") && 
                            fieldInsn.owner.equals(classWrapper.getName())) {
                            
                            // Find the array creation and all stores
                            AbstractInsnNode current = findArrayCreation(fieldInsn);
                            if (current != null) {
                                insnsToRemove.add(current); // Add array creation
                                
                                // Add all string stores to the array
                                for (AbstractInsnNode store = current.getNext(); store != fieldInsn.getNext(); store = store.getNext()) {
                                    insnsToRemove.add(store);
                                }
                                
                                modified = true;
                            }
                        }
                    }
                }
                
                // Remove all identified instructions
                for (AbstractInsnNode insn : insnsToRemove) {
                    methodNode.instructions.remove(insn);
                }
                
                // Remove the nothing_to_see_here field itself
                classWrapper.getFieldsAsNodes().remove(fieldNode);
                break;
            }
        }
        
        return modified;
    }
    
    /**
     * Find the array creation instruction for a field
     */
    private AbstractInsnNode findArrayCreation(FieldInsnNode fieldInsn) {
        AbstractInsnNode current = fieldInsn.getPrevious();
        
        // Work backwards to find the array creation
        while (current != null) {
            if (current instanceof TypeInsnNode && 
                current.getOpcode() == ANEWARRAY && 
                ((TypeInsnNode) current).desc.equals("java/lang/String")) {
                
                // Check for the array size push
                AbstractInsnNode prev = getPreviousRealInsn(current);
                if (prev != null && isPushingIntValue(prev)) {
                    return prev;
                }
            }
            
            current = current.getPrevious();
        }
        
        return null;
    }
    
    /**
     * Remove ByteBuffer.wrap transformations in the static initializer
     */
    private boolean removeByteBufferWrapTransformations(MethodNode methodNode) {
        boolean modified = false;
        
        // Look for ByteBuffer.wrap sequences
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Store next before potential modification
            
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                
                if (methodInsn.owner.equals("java/nio/ByteBuffer") && 
                    methodInsn.name.equals("wrap") && 
                    methodInsn.desc.equals("([B)Ljava/nio/ByteBuffer;")) {
                    
                    // This is a ByteBuffer.wrap call - find the full sequence
                    List<AbstractInsnNode> sequenceInsns = findByteBufferSequence(methodInsn);
                    if (!sequenceInsns.isEmpty()) {
                        // Remove all instructions in the sequence
                        for (AbstractInsnNode toRemove : sequenceInsns) {
                            methodNode.instructions.remove(toRemove);
                        }
                        
                        modified = true;
                        
                        // Skip to after the removed sequence
                        next = sequenceInsns.get(sequenceInsns.size() - 1).getNext();
                    }
                }
            }
            
            insn = next;
        }
        
        return modified;
    }
    
    /**
     * Find a complete ByteBuffer.wrap transformation sequence
     */
    private List<AbstractInsnNode> findByteBufferSequence(MethodInsnNode wrapMethodInsn) {
        List<AbstractInsnNode> result = new ArrayList<>();
        
        // First, add the ByteBuffer.wrap call
        result.add(wrapMethodInsn);
        
        // Find the byte array argument (typically a method call)
        AbstractInsnNode byteArrayInsn = getPreviousRealInsn(wrapMethodInsn);
        if (byteArrayInsn instanceof MethodInsnNode && ((MethodInsnNode) byteArrayInsn).desc.equals("()[B")) {
            result.add(byteArrayInsn);
        }
        
        // Now find the rest of the sequence: asCharBuffer, toString, putstatic
        AbstractInsnNode current = wrapMethodInsn.getNext();
        while (current != null) {
            if (current instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) current;
                
                if (methodInsn.owner.equals("java/nio/ByteBuffer") && 
                    methodInsn.name.equals("asCharBuffer")) {
                    result.add(methodInsn);
                } else if (methodInsn.owner.equals("java/nio/CharBuffer") && 
                          methodInsn.name.equals("toString")) {
                    result.add(methodInsn);
                } else {
                    break;
                }
            } else if (current instanceof FieldInsnNode && current.getOpcode() == PUTSTATIC) {
                // Found the field store - this is the end of the sequence
                result.add(current);
                break;
            } else if (!(current instanceof LabelNode || 
                        current instanceof LineNumberNode || 
                        current instanceof FrameNode)) {
                break;
            }
            
            current = current.getNext();
        }
        
        return result;
    }
    
    /**
     * Remove random number initializations in the static initializer
     */
    private boolean removeRandomNumberInitializations(MethodNode methodNode) {
        boolean modified = false;
        
        // Look for Random creation and nextInt calls
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Store next before potential modification
            
            if (insn instanceof TypeInsnNode && 
                insn.getOpcode() == NEW && 
                ((TypeInsnNode) insn).desc.equals("java/util/Random")) {
                
                // This is a Random creation - find the full sequence
                List<AbstractInsnNode> sequenceInsns = findRandomSequence(insn);
                if (!sequenceInsns.isEmpty()) {
                    // Remove all instructions in the sequence
                    for (AbstractInsnNode toRemove : sequenceInsns) {
                        methodNode.instructions.remove(toRemove);
                    }
                    
                    modified = true;
                    
                    // Skip to after the removed sequence
                    next = sequenceInsns.get(sequenceInsns.size() - 1).getNext();
                }
            }
            
            insn = next;
        }
        
        return modified;
    }
    
    /**
     * Find a complete Random initialization sequence
     */
    private List<AbstractInsnNode> findRandomSequence(AbstractInsnNode newInsn) {
        List<AbstractInsnNode> result = new ArrayList<>();
        
        // First, add the NEW instruction
        result.add(newInsn);
        
        // Look for DUP, seed push, INVOKESPECIAL <init>
        AbstractInsnNode current = newInsn.getNext();
        boolean foundInit = false;
        
        while (current != null && !foundInit) {
            if (current instanceof InsnNode && current.getOpcode() == DUP) {
                result.add(current);
            } else if (current instanceof LdcInsnNode && ((LdcInsnNode) current).cst instanceof Long) {
                result.add(current);
            } else if (current instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) current;
                
                if (methodInsn.owner.equals("java/util/Random") && 
                    methodInsn.name.equals("<init>")) {
                    result.add(methodInsn);
                    foundInit = true;
                } else {
                    break;
                }
            } else if (!(current instanceof LabelNode || 
                        current instanceof LineNumberNode || 
                        current instanceof FrameNode)) {
                break;
            }
            
            current = current.getNext();
        }
        
        if (!foundInit) {
            return Collections.emptyList();
        }
        
        // Now look for nextInt and field store
        while (current != null) {
            if (current instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) current;
                
                if (methodInsn.owner.equals("java/util/Random") && 
                    methodInsn.name.equals("nextInt")) {
                    result.add(methodInsn);
                } else {
                    break;
                }
            } else if (current instanceof FieldInsnNode && current.getOpcode() == PUTSTATIC) {
                // Found the field store - this is the end of the sequence
                result.add(current);
                break;
            } else if (!(current instanceof LabelNode || 
                        current instanceof LineNumberNode || 
                        current instanceof FrameNode)) {
                break;
            }
            
            current = current.getNext();
        }
        
        return result;
    }
    
    /**
     * Check if the static initializer is empty (only contains a RETURN)
     */
    private boolean isClinitEmpty(MethodNode methodNode) {
        int realInstructions = 0;
        
        for (AbstractInsnNode insn : methodNode.instructions) {
            if (!(insn instanceof LabelNode) && 
                !(insn instanceof LineNumberNode) && 
                !(insn instanceof FrameNode)) {
                
                // Count non-return instructions
                if (insn.getOpcode() != RETURN) {
                    realInstructions++;
                }
            }
        }
        
        return realInstructions == 0;
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