package dead.owner.deobf.transformers;

import dead.owner.deobf.Run;
import dead.owner.deobf.utils.wrapper.ClassWrapper;
import dead.owner.deobf.utils.wrapper.FieldWrapper;
import dead.owner.deobf.utils.wrapper.MethodWrapper;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Transformer to restore invokedynamic instructions to normal method calls
 */
public class InvokeDynamicRestorer implements Transformer, Opcodes {
    
    @Override
    public void transform(ClassWrapper classWrapper) {
        // Find bootstrap methods
        Map<String, MethodNode> bootstrapMethods = findBootstrapMethods(classWrapper);
        if (bootstrapMethods.isEmpty()) {
            return;
        }
        
        // Find callsite fields
        List<FieldNode> callsiteFields = findCallsiteFields(classWrapper);
        
        // Process each method
        int restored = 0;
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            restored += restoreInvokeDynamics(methodWrapper, bootstrapMethods);
        }
        
        // Remove bootstrap methods
        for (MethodNode method : bootstrapMethods.values()) {
            classWrapper.getMethodsAsNodes().remove(method);
        }
        
        // Remove callsite fields
        for (FieldNode field : callsiteFields) {
            classWrapper.getFieldsAsNodes().remove(field);
        }
        
        if (restored > 0) {
            Run.log(classWrapper.getName() + " | Restored " + restored + " invokedynamic calls");
        }
    }
    
    /**
     * Find bootstrap methods in the class
     */
    private Map<String, MethodNode> findBootstrapMethods(ClassWrapper classWrapper) {
        Map<String, MethodNode> bootstrapMethods = new HashMap<>();
        
        for (MethodNode method : classWrapper.getMethodsAsNodes()) {
            // Check if this is a bootstrap method (returns CallSite)
            if (method.desc.equals("(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;")) {
                bootstrapMethods.put(method.name, method);
            }
        }
        
        return bootstrapMethods;
    }
    
    /**
     * Find callsite fields in the class
     */
    private List<FieldNode> findCallsiteFields(ClassWrapper classWrapper) {
        List<FieldNode> callsiteFields = new ArrayList<>();
        
        for (FieldWrapper fieldWrapper : classWrapper.getFields()) {
            String desc = fieldWrapper.getDescriptor();
            if (desc.equals("Ljava/lang/invoke/MutableCallSite;") || 
                desc.equals("Ljava/lang/invoke/CallSite;")) {
                callsiteFields.add(fieldWrapper.getFieldNode());
            }
        }
        
        return callsiteFields;
    }
    
    /**
     * Restore invokedynamic calls in a method
     * 
     * @return Number of restored calls
     */
    private int restoreInvokeDynamics(MethodWrapper methodWrapper, Map<String, MethodNode> bootstrapMethods) {
        InsnList instructions = methodWrapper.getInstructions();
        int count = 0;
        
        for (AbstractInsnNode insn = instructions.getFirst(); insn != null;) {
            AbstractInsnNode next = insn.getNext();
            
            if (insn instanceof InvokeDynamicInsnNode) {
                InvokeDynamicInsnNode invokeDynamicInsn = (InvokeDynamicInsnNode) insn;
                Handle bsm = invokeDynamicInsn.bsm;
                
                // Check if this uses one of our bootstrap methods
                if (bootstrapMethods.containsKey(bsm.getName())) {
                    MethodNode bootstrapMethod = bootstrapMethods.get(bsm.getName());
                    
                    // Extract the original method parameters
                    Map<String, String> methodDetails = extractMethodDetailsFromBootstrap(bootstrapMethod);
                    if (!methodDetails.isEmpty()) {
                        // Create the appropriate method invocation
                        MethodInsnNode replacementInsn = createMethodInvocation(
                            invokeDynamicInsn, 
                            methodDetails.getOrDefault("owner", ""),
                            methodDetails.getOrDefault("name", ""),
                            methodDetails.getOrDefault("desc", "")
                        );
                        
                        if (replacementInsn != null) {
                            instructions.set(invokeDynamicInsn, replacementInsn);
                            count++;
                        }
                    }
                }
            }
            
            insn = next;
        }
        
        return count;
    }
    
    /**
     * Extract original method details from the bootstrap method
     */
    private Map<String, String> extractMethodDetailsFromBootstrap(MethodNode bootstrapMethod) {
        Map<String, String> details = new HashMap<>();
        
        // We need to analyze the bootstrap method to find the original method details
        for (AbstractInsnNode insn : bootstrapMethod.instructions) {
            if (insn instanceof LdcInsnNode) {
                LdcInsnNode ldcInsn = (LdcInsnNode) insn;
                if (ldcInsn.cst instanceof String) {
                    String value = (String) ldcInsn.cst;
                    
                    // Try to determine what this string represents
                    if (value.contains(".") && !details.containsKey("owner")) {
                        // This is likely a class name
                        details.put("owner", value.replace('.', '/'));
                    } else if (!details.containsKey("name")) {
                        // This is likely a method name
                        details.put("name", value);
                    } else if (!details.containsKey("desc")) {
                        // This is likely a method descriptor
                        details.put("desc", value);
                    }
                }
            }
        }
        
        return details;
    }
    
    /**
     * Create a method invocation instruction to replace the invokedynamic
     */
    private MethodInsnNode createMethodInvocation(InvokeDynamicInsnNode invokeDynamicInsn, 
                                                 String owner, String name, String desc) {
        if (owner.isEmpty() || name.isEmpty() || desc.isEmpty()) {
            return null;
        }
        
        int opcode;
        String methodDesc = desc;
        
        // Determine opcode based on invokedynamic name
        if (invokeDynamicInsn.name.equals("v")) {
            opcode = INVOKEVIRTUAL;
            
            // For virtual methods, we need to adjust the descriptor
            // The invokedynamic descriptor has the instance as the first argument
            Type[] argTypes = Type.getArgumentTypes(invokeDynamicInsn.desc);
            Type returnType = Type.getReturnType(desc);
            
            if (argTypes.length > 0) {
                // Skip the first argument (instance)
                Type[] actualArgTypes = new Type[argTypes.length - 1];
                if (actualArgTypes.length > 0) {
                    System.arraycopy(argTypes, 1, actualArgTypes, 0, actualArgTypes.length);
                }
                methodDesc = Type.getMethodDescriptor(returnType, actualArgTypes);
            }
        } else {
            opcode = INVOKESTATIC;
        }
        
        return new MethodInsnNode(opcode, owner, name, methodDesc, false);
    }
}