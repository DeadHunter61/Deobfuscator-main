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
 * Transformer to remove dummy classes and proxy methods inserted by Colonial Obfuscator.
 * Colonial often adds:
 * 1. Dummy fields that are never used
 * 2. Proxy methods that just delegate to other methods
 * 3. Fake methods that don't do anything useful
 */
public class ColonialDummyClassRemover implements Transformer, Opcodes {
    
    @Override
    public void transform(ClassWrapper classWrapper) {
        // First remove dummy fields
        int removedFields = removeDummyFields(classWrapper);
        
        // Then remove proxy methods
        int removedMethods = removeProxyMethods(classWrapper);
        
        if (removedFields > 0 || removedMethods > 0) {
            Run.log(classWrapper.getName() + " | Removed " + removedFields + 
                   " dummy fields and " + removedMethods + " proxy methods");
        }
    }
    
    /**
     * Remove dummy fields that are never used
     */
    private int removeDummyFields(ClassWrapper classWrapper) {
        // First identify all fields that are actually accessed
        Set<String> usedFields = findUsedFields(classWrapper);
        
        // Then remove fields that aren't accessed
        List<FieldNode> fieldsToRemove = new ArrayList<>();
        for (FieldNode fieldNode : classWrapper.getFieldsAsNodes()) {
            String fieldKey = fieldNode.name + ":" + fieldNode.desc;
            
            if (!usedFields.contains(fieldKey)) {
                // Check if this looks like a dummy field
                if (isDummyField(fieldNode)) {
                    fieldsToRemove.add(fieldNode);
                }
            }
        }
        
        // Remove the identified fields
        for (FieldNode field : fieldsToRemove) {
            classWrapper.getFieldsAsNodes().remove(field);
        }
        
        return fieldsToRemove.size();
    }
    
    /**
     * Remove proxy methods that just delegate to other methods
     */
    private int removeProxyMethods(ClassWrapper classWrapper) {
        // First identify methods that are actually called
        Set<String> calledMethods = findCalledMethods(classWrapper);
        
        // Then identify and remove proxy methods
        List<MethodNode> methodsToRemove = new ArrayList<>();
        Map<String, MethodNode> methodReplacements = new HashMap<>();
        
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            MethodNode methodNode = methodWrapper.getMethodNode();
            String methodKey = methodNode.name + methodNode.desc;
            
            // Skip constructors and methods that are called
            if (methodNode.name.equals("<init>") || methodNode.name.equals("<clinit>") || 
                calledMethods.contains(methodKey)) {
                continue;
            }
            
            // Check if this is a proxy method
            MethodNode targetMethod = isProxyMethod(classWrapper, methodNode);
            if (targetMethod != null) {
                methodsToRemove.add(methodNode);
                methodReplacements.put(methodKey, targetMethod);
            } 
            // Check if this is a useless method
            else if (isUselessMethod(methodNode)) {
                methodsToRemove.add(methodNode);
            }
        }
        
        // If we found proxy methods, update calls to them
        if (!methodReplacements.isEmpty()) {
            for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
                MethodNode methodNode = methodWrapper.getMethodNode();
                
                // Skip methods we're removing
                if (methodsToRemove.contains(methodNode)) {
                    continue;
                }
                
                // Update calls to proxy methods
                for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn instanceof MethodInsnNode) {
                        MethodInsnNode methodInsn = (MethodInsnNode) insn;
                        
                        // Only rewrite calls to methods in this class
                        if (methodInsn.owner.equals(classWrapper.getName())) {
                            String calledMethodKey = methodInsn.name + methodInsn.desc;
                            
                            if (methodReplacements.containsKey(calledMethodKey)) {
                                MethodNode targetMethod = methodReplacements.get(calledMethodKey);
                                methodInsn.name = targetMethod.name;
                                methodInsn.desc = targetMethod.desc;
                            }
                        }
                    }
                }
            }
        }
        
        // Remove the identified methods
        for (MethodNode method : methodsToRemove) {
            classWrapper.getMethodsAsNodes().remove(method);
        }
        
        return methodsToRemove.size();
    }
    
    /**
     * Find all fields that are actually used in the class
     */
    private Set<String> findUsedFields(ClassWrapper classWrapper) {
        Set<String> usedFields = new HashSet<>();
        
        // Check field accesses in all methods
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            for (AbstractInsnNode insn : methodWrapper.getMethodNode().instructions) {
                if (insn instanceof FieldInsnNode) {
                    FieldInsnNode fieldInsn = (FieldInsnNode) insn;
                    
                    // Consider fields in this class and potentially its superclasses
                    String fieldKey = fieldInsn.name + ":" + fieldInsn.desc;
                    usedFields.add(fieldKey);
                }
            }
        }
        
        return usedFields;
    }
    
    /**
     * Find all methods that are actually called in the class
     */
    private Set<String> findCalledMethods(ClassWrapper classWrapper) {
        Set<String> calledMethods = new HashSet<>();
        
        // Check method calls in all methods
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            for (AbstractInsnNode insn : methodWrapper.getMethodNode().instructions) {
                if (insn instanceof MethodInsnNode) {
                    MethodInsnNode methodInsn = (MethodInsnNode) insn;
                    
                    // Consider methods in this class
                    if (methodInsn.owner.equals(classWrapper.getName())) {
                        String methodKey = methodInsn.name + methodInsn.desc;
                        calledMethods.add(methodKey);
                    }
                }
            }
        }
        
        return calledMethods;
    }
    
    /**
     * Check if a field is likely a dummy field
     */
    private boolean isDummyField(FieldNode fieldNode) {
        // Colonial often adds fake fields with these characteristics:
        // 1. Static final fields with random-looking names
        // 2. Fields with simple values (0, 1, null, empty strings) that aren't used
        
        // Check if it's static final
        boolean isStaticFinal = (fieldNode.access & (ACC_STATIC | ACC_FINAL)) == (ACC_STATIC | ACC_FINAL);
        
        // Check if it has a random-looking name
        boolean hasRandomName = fieldNode.name.matches("[a-zA-Z][a-zA-Z0-9]{5,}");
        
        // Check if it has a simple type that might be a dummy field
        boolean hasSimpleType = fieldNode.desc.equals("I") || 
                              fieldNode.desc.equals("J") || 
                              fieldNode.desc.equals("Z") || 
                              fieldNode.desc.equals("Ljava/lang/String;") || 
                              fieldNode.desc.equals("Ljava/lang/Object;");
        
        return (isStaticFinal && hasRandomName) || (hasRandomName && hasSimpleType);
    }
    
    /**
     * Check if a method is a proxy for another method
     * 
     * @return The target method if this is a proxy, null otherwise
     */
    private MethodNode isProxyMethod(ClassWrapper classWrapper, MethodNode methodNode) {
        // A proxy method typically:
        // 1. Loads the arguments
        // 2. Calls another method with those same arguments
        // 3. Returns the result of that call
        
        // Check if the method is small (proxy methods are usually small)
        int realInstructions = countRealInstructions(methodNode);
        if (realInstructions > 10) {
            return null; // Too many instructions for a proxy
        }
        
        // Look for a pattern like:
        // [load args] -> INVOKESTATIC/INVOKEVIRTUAL -> RETURN
        AbstractInsnNode lastInsn = null;
        AbstractInsnNode returnInsn = null;
        
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if ((insn.getOpcode() >= IRETURN && insn.getOpcode() <= RETURN)) {
                returnInsn = insn;
                break;
            }
            lastInsn = insn;
        }
        
        if (lastInsn instanceof MethodInsnNode && returnInsn != null) {
            MethodInsnNode methodInsn = (MethodInsnNode) lastInsn;
            
            // Check if the method called is in this class
            if (methodInsn.owner.equals(classWrapper.getName())) {
                // Find the target method
                for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
                    MethodNode targetMethod = methodWrapper.getMethodNode();
                    
                    if (targetMethod.name.equals(methodInsn.name) && 
                        targetMethod.desc.equals(methodInsn.desc)) {
                        return targetMethod;
                    }
                }
            }
        }
        
        return null;
    }
    
    /**
     * Check if a method is useless (does nothing meaningful)
     */
    private boolean isUselessMethod(MethodNode methodNode) {
        // Useless methods typically:
        // 1. Return a constant
        // 2. Have very few real instructions
        // 3. Have random-looking names
        
        // Check if the method has a random-looking name
        boolean hasRandomName = methodNode.name.matches("[a-zA-Z][a-zA-Z0-9]{5,}");
        
        // Check if the method is small
        int realInstructions = countRealInstructions(methodNode);
        if (realInstructions > 5) {
            return false; // Too many instructions to be considered useless
        }
        
        // Check if the method just returns a constant
        boolean returnsConstant = false;
        AbstractInsnNode lastRealInsn = null;
        
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (!(insn instanceof LabelNode) && 
                !(insn instanceof LineNumberNode) && 
                !(insn instanceof FrameNode)) {
                lastRealInsn = insn;
            }
        }
        
        if (lastRealInsn != null && lastRealInsn.getOpcode() >= IRETURN && lastRealInsn.getOpcode() <= RETURN) {
            AbstractInsnNode prevInsn = getPreviousRealInsn(lastRealInsn);
            
            if (prevInsn != null) {
                returnsConstant = isConstant(prevInsn);
            } else if (lastRealInsn.getOpcode() == RETURN) {
                // Void method with just RETURN
                returnsConstant = true;
            }
        }
        
        return hasRandomName && returnsConstant;
    }
    
    /**
     * Count real instructions in a method (not labels, frames, etc.)
     */
    private int countRealInstructions(MethodNode methodNode) {
        int count = 0;
        
        for (AbstractInsnNode insn : methodNode.instructions) {
            if (!(insn instanceof LabelNode) && 
                !(insn instanceof LineNumberNode) && 
                !(insn instanceof FrameNode)) {
                count++;
            }
        }
        
        return count;
    }
    
    /**
     * Get the previous real instruction (skip labels, frames, etc.)
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
     * Check if an instruction is a constant
     */
    private boolean isConstant(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        return (opcode >= ICONST_M1 && opcode <= ICONST_5) ||
               (opcode >= LCONST_0 && opcode <= LCONST_1) ||
               (opcode >= FCONST_0 && opcode <= FCONST_2) ||
               (opcode >= DCONST_0 && opcode <= DCONST_1) ||
               opcode == ACONST_NULL ||
               opcode == BIPUSH || 
               opcode == SIPUSH ||
               insn instanceof LdcInsnNode;
    }
}