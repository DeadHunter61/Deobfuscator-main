package dead.owner.deobf.transformers.colonial;

import dead.owner.deobf.Run;
import dead.owner.deobf.utils.wrapper.ClassWrapper;
import dead.owner.deobf.utils.wrapper.MethodWrapper;
import dead.owner.deobf.transformers.Transformer;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.util.*;

/**
 * Transformer to resolve invokedynamic instructions inserted by Colonial Obfuscator.
 * Colonial uses invokedynamic to hide method calls and make code harder to understand.
 */
public class ColonialInvokeDynamicResolver implements Transformer, Opcodes {
    
    @Override
    public void transform(ClassWrapper classWrapper) {
        // First identify bootstrap methods
        List<MethodNode> bootstrapMethods = findBootstrapMethods(classWrapper);
        if (bootstrapMethods.isEmpty()) {
            return;
        }
        
        // Process each method to resolve invokedynamic instructions
        int restoredTotal = 0;
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            int restored = resolveInvokeDynamics(classWrapper, methodWrapper, bootstrapMethods);
            restoredTotal += restored;
        }
        
        // If we've restored invokedynamic instructions, remove the bootstrap methods
        if (restoredTotal > 0) {
            for (MethodNode bootstrapMethod : bootstrapMethods) {
                classWrapper.getMethodsAsNodes().remove(bootstrapMethod);
            }
            Run.log(classWrapper.getName() + " | Resolved " + restoredTotal + " invokedynamic instructions");
        }
    }
    
    /**
     * Find bootstrap methods in the class
     */
    private List<MethodNode> findBootstrapMethods(ClassWrapper classWrapper) {
        List<MethodNode> bootstrapMethods = new ArrayList<>();
        
        for (MethodNode methodNode : classWrapper.getMethodsAsNodes()) {
            // Check if this looks like a bootstrap method
            if (isBootstrapMethod(methodNode)) {
                bootstrapMethods.add(methodNode);
            }
        }
        
        return bootstrapMethods;
    }
    
    /**
     * Check if a method is likely a bootstrap method
     */
    private boolean isBootstrapMethod(MethodNode methodNode) {
        // Check if the method returns CallSite
        Type returnType = Type.getReturnType(methodNode.desc);
        if (!returnType.getDescriptor().equals("Ljava/lang/invoke/CallSite;")) {
            return false;
        }
        
        // Check for typical bootstrap method signature
        String desc = methodNode.desc;
        boolean hasCorrectParams = desc.equals("(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;") ||
                                 desc.equals("(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/Object;)Ljava/lang/invoke/CallSite;") ||
                                 desc.equals("(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;");
        
        if (!hasCorrectParams) {
            return false;
        }
        
        // Check for common bootstrap method instructions
        boolean hasMethodHandlesLookup = false;
        boolean createsMutableCallSite = false;
        
        for (AbstractInsnNode insn : methodNode.instructions) {
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                
                if (methodInsn.owner.equals("java/lang/invoke/MethodHandles$Lookup") && 
                   (methodInsn.name.equals("findStatic") || 
                    methodInsn.name.equals("findVirtual") || 
                    methodInsn.name.equals("findConstructor"))) {
                    hasMethodHandlesLookup = true;
                } else if (methodInsn.owner.equals("java/lang/invoke/MutableCallSite") && 
                          methodInsn.name.equals("<init>")) {
                    createsMutableCallSite = true;
                }
            }
        }
        
        return hasMethodHandlesLookup || createsMutableCallSite;
    }
    
    /**
     * Resolve invokedynamic instructions in a method
     */
    private int resolveInvokeDynamics(ClassWrapper classWrapper, MethodWrapper methodWrapper, 
                                    List<MethodNode> bootstrapMethods) {
        MethodNode methodNode = methodWrapper.getMethodNode();
        int resolved = 0;
        
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Save next before potential modification
            
            if (insn instanceof InvokeDynamicInsnNode) {
                InvokeDynamicInsnNode indyInsn = (InvokeDynamicInsnNode) insn;
                
                // Try to resolve this invokedynamic instruction
                boolean success = resolveIndy(classWrapper, methodNode, indyInsn, bootstrapMethods);
                if (success) {
                    resolved++;
                }
            }
            
            insn = next;
        }
        
        return resolved;
    }
    
    /**
     * Resolve a single invokedynamic instruction
     */
    private boolean resolveIndy(ClassWrapper classWrapper, MethodNode methodNode, 
                             InvokeDynamicInsnNode indyInsn, List<MethodNode> bootstrapMethods) {
        Handle bsmHandle = indyInsn.bsm;
        
        // Check if this invokedynamic uses one of our bootstrap methods
        if (!bsmHandle.getOwner().equals(classWrapper.getName())) {
            return false;
        }
        
        // Find the bootstrap method
        MethodNode bootstrapMethod = null;
        for (MethodNode method : bootstrapMethods) {
            if (method.name.equals(bsmHandle.getName()) && method.desc.equals(bsmHandle.getDesc())) {
                bootstrapMethod = method;
                break;
            }
        }
        
        if (bootstrapMethod == null) {
            return false;
        }
        
        // Analyze the bootstrap method to determine the real method being called
        Map<String, String> realMethodInfo = analyzeBootstrapMethod(bootstrapMethod);
        
        // If we couldn't determine all details, try to extract them from the invokedynamic name
        if (realMethodInfo.get("owner") == null || realMethodInfo.get("name") == null) {
            // Colonial often encodes information in the invokedynamic name
            String[] parts = indyInsn.name.split("_");
            if (parts.length >= 2) {
                if (realMethodInfo.get("owner") == null) {
                    realMethodInfo.put("owner", parts[0].replace('.', '/'));
                }
                if (realMethodInfo.get("name") == null) {
                    realMethodInfo.put("name", parts[1]);
                }
            }
        }
        
        // If we still don't have an owner, use the current class
        if (realMethodInfo.get("owner") == null) {
            realMethodInfo.put("owner", classWrapper.getName());
        }
        
        // If we still don't have a name, use a placeholder
        if (realMethodInfo.get("name") == null) {
            realMethodInfo.put("name", "unknown_" + indyInsn.name);
        }
        
        // If we don't have a descriptor, use the invokedynamic descriptor
        if (realMethodInfo.get("desc") == null) {
            realMethodInfo.put("desc", indyInsn.desc);
        }
        
        // Create the appropriate method invocation
        AbstractInsnNode replacement = createMethodInvocation(
            indyInsn, 
            realMethodInfo.get("owner"), 
            realMethodInfo.get("name"), 
            realMethodInfo.get("desc"), 
            realMethodInfo.getOrDefault("opcode", null)
        );
        
        if (replacement != null) {
            // Replace the invokedynamic with the direct method call
            methodNode.instructions.set(indyInsn, replacement);
            return true;
        }
        
        return false;
    }
    
    /**
     * Analyze a bootstrap method to determine the real method being called
     */
    private Map<String, String> analyzeBootstrapMethod(MethodNode bootstrapMethod) {
        Map<String, String> result = new HashMap<>();
        String owner = null;
        String name = null;
        String desc = null;
        String opcode = null;
        
        // Colonial often stores the real method information as constants
        for (AbstractInsnNode insn : bootstrapMethod.instructions) {
            // Look for LDC instructions with method information
            if (insn instanceof LdcInsnNode) {
                LdcInsnNode ldcInsn = (LdcInsnNode) insn;
                if (ldcInsn.cst instanceof String) {
                    String value = (String) ldcInsn.cst;
                    
                    if (value.contains("/") || value.contains(".")) {
                        // This is likely the owner class name
                        owner = value.replace('.', '/');
                    } else if (!value.startsWith("(")) {
                        // This is likely the method name
                        name = value;
                    }
                } else if (ldcInsn.cst instanceof Type) {
                    // This might be part of the method descriptor
                    Type type = (Type) ldcInsn.cst;
                    if (type.getSort() == Type.METHOD) {
                        desc = type.getDescriptor();
                    }
                }
            }
            
            // Look for specific lookup method calls
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                if (methodInsn.owner.equals("java/lang/invoke/MethodHandles$Lookup")) {
                    if (methodInsn.name.equals("findStatic")) {
                        opcode = Integer.toString(INVOKESTATIC);
                    } else if (methodInsn.name.equals("findVirtual")) {
                        opcode = Integer.toString(INVOKEVIRTUAL);
                    } else if (methodInsn.name.equals("findSpecial")) {
                        opcode = Integer.toString(INVOKESPECIAL);
                    } else if (methodInsn.name.equals("findConstructor")) {
                        opcode = Integer.toString(INVOKESPECIAL);
                        name = "<init>";
                    }
                }
            }
        }
        
        if (owner != null) result.put("owner", owner);
        if (name != null) result.put("name", name);
        if (desc != null) result.put("desc", desc);
        if (opcode != null) result.put("opcode", opcode);
        
        return result;
    }
    
    /**
     * Create a method invocation instruction to replace an invokedynamic
     */
    private AbstractInsnNode createMethodInvocation(InvokeDynamicInsnNode indyInsn, 
                                                  String owner, String name, String desc, String opcodeStr) {
        if (owner == null || name == null || desc == null) {
            return null;
        }
        
        // Determine the opcode
        int opcode;
        if (opcodeStr != null) {
            opcode = Integer.parseInt(opcodeStr);
        } else if (name.equals("<init>")) {
            opcode = INVOKESPECIAL;
        } else {
            // Default to INVOKESTATIC - this is common in Colonial Obfuscator
            opcode = INVOKESTATIC;
        }
        
        // Create the appropriate method call
        return new MethodInsnNode(opcode, owner, name, desc, false);
    }
}