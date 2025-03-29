package dead.owner.deobf.transformers.skid;

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
 * Transformer to restore invokedynamic instructions obfuscated by SkidFuscator.
 * SkidFuscator uses invokedynamic to hide method calls and make code harder to understand.
 */
public class SkidIndyRemapper implements Transformer, Opcodes {
    
    @Override
    public void transform(ClassWrapper classWrapper) {
        // First identify bootstrap methods
        List<MethodNode> bootstrapMethods = findBootstrapMethods(classWrapper);
        if (bootstrapMethods.isEmpty()) {
            return;
        }
        
        // Process each method to restore invokedynamic instructions
        int restoredTotal = 0;
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            int restored = restoreInvokeDynamics(classWrapper, methodWrapper, bootstrapMethods);
            restoredTotal += restored;
        }
        
        // If we've restored invokedynamic instructions, remove the bootstrap methods
        if (restoredTotal > 0) {
            for (MethodNode bootstrapMethod : bootstrapMethods) {
                classWrapper.getMethodsAsNodes().remove(bootstrapMethod);
            }
            Run.log(classWrapper.getName() + " | Restored " + restoredTotal + " invokedynamic instructions");
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
        
        // Check for typical bootstrap method instructions
        for (AbstractInsnNode insn : methodNode.instructions) {
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                if (methodInsn.owner.equals("java/lang/invoke/MethodHandles$Lookup") && 
                   (methodInsn.name.equals("findStatic") || 
                    methodInsn.name.equals("findVirtual") || 
                    methodInsn.name.equals("findConstructor"))) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Restore invokedynamic instructions in a method
     */
    private int restoreInvokeDynamics(ClassWrapper classWrapper, MethodWrapper methodWrapper, List<MethodNode> bootstrapMethods) {
        MethodNode methodNode = methodWrapper.getMethodNode();
        int restored = 0;
        
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Store next before potential modification
            
            if (insn instanceof InvokeDynamicInsnNode) {
                InvokeDynamicInsnNode indyInsn = (InvokeDynamicInsnNode) insn;
                
                // Try to restore this invokedynamic instruction
                boolean success = restoreIndy(classWrapper, methodNode, indyInsn, bootstrapMethods);
                if (success) {
                    restored++;
                }
            }
            
            insn = next;
        }
        
        return restored;
    }
    
    /**
     * Restore a single invokedynamic instruction
     */
    private boolean restoreIndy(ClassWrapper classWrapper, MethodNode methodNode, InvokeDynamicInsnNode indyInsn, List<MethodNode> bootstrapMethods) {
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
        if (realMethodInfo.isEmpty()) {
            return false;
        }
        
        // Create the appropriate method invocation
        AbstractInsnNode replacement = createMethodInvocation(
            indyInsn, 
            realMethodInfo.get("owner"), 
            realMethodInfo.get("name"), 
            realMethodInfo.get("desc")
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
        
        for (AbstractInsnNode insn : bootstrapMethod.instructions) {
            // Look for LDC instructions with method owner and name
            if (insn instanceof LdcInsnNode) {
                LdcInsnNode ldcInsn = (LdcInsnNode) insn;
                if (ldcInsn.cst instanceof String) {
                    String value = (String) ldcInsn.cst;
                    
                    if (value.contains("/") || value.contains(".")) {
                        // This is likely the owner class name
                        owner = value.replace('.', '/');
                    } else {
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
            
            // Look for findStatic/findVirtual calls for more information
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                if (methodInsn.owner.equals("java/lang/invoke/MethodHandles$Lookup")) {
                    if (methodInsn.name.equals("findStatic")) {
                        result.put("opcode", Integer.toString(INVOKESTATIC));
                    } else if (methodInsn.name.equals("findVirtual")) {
                        result.put("opcode", Integer.toString(INVOKEVIRTUAL));
                    } else if (methodInsn.name.equals("findConstructor")) {
                        result.put("opcode", Integer.toString(INVOKESPECIAL));
                        name = "<init>";
                    } else if (methodInsn.name.equals("findSpecial")) {
                        result.put("opcode", Integer.toString(INVOKESPECIAL));
                    }
                }
            }
        }
        
        if (owner != null) result.put("owner", owner);
        if (name != null) result.put("name", name);
        if (desc != null) result.put("desc", desc);
        
        return result;
    }
    
    /**
     * Create a method invocation instruction to replace an invokedynamic
     */
    private AbstractInsnNode createMethodInvocation(InvokeDynamicInsnNode indyInsn, String owner, String name, String desc) {
        if (owner == null || name == null) {
            // Try to extract information from the invokedynamic itself
            if (indyInsn.name.contains("_")) {
                String[] parts = indyInsn.name.split("_");
                if (parts.length >= 2) {
                    if (owner == null) owner = parts[0];
                    if (name == null) name = parts[1];
                }
            }
        }
        
        if (owner == null || name == null) {
            return null;
        }
        
        // If we don't have a desc, try to derive it from the invokedynamic
        if (desc == null) {
            desc = indyInsn.desc;
        }
        
        // Determine the opcode based on the method name and bootstrap analysis
        int opcode;
        if (name.equals("<init>")) {
            opcode = INVOKESPECIAL;
        } else {
            // Default to INVOKESTATIC - this is common for SkidFuscator
            opcode = INVOKESTATIC;
        }
        
        // Create the appropriate method call
        return new MethodInsnNode(opcode, owner, name, desc, false);
    }
}