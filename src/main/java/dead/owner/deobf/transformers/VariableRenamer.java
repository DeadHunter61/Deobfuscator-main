package dead.owner.deobf.transformers;

import dead.owner.deobf.Run;
import dead.owner.deobf.utils.wrapper.ClassWrapper;
import dead.owner.deobf.utils.wrapper.FieldWrapper;
import dead.owner.deobf.utils.wrapper.MethodWrapper;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Transformer to rename obfuscated variables to more meaningful names
 */
public class VariableRenamer implements Transformer, Opcodes {
    
    private static final Pattern OBFUSCATED_FIELD_PATTERN = 
        Pattern.compile("^[a-zA-Z][0-9a-zA-Z]{5,}$"); // Matches field names like fgwhqejzgb, CPdSiwPe7j
    
    private static final Pattern OBFUSCATED_METHOD_PATTERN = 
        Pattern.compile("^[a-z]{2,}$"); // Matches method names like gc, asd, gcm
    
    private static final Pattern OBFUSCATED_PARAM_PATTERN = 
        Pattern.compile("^var[0-9]+$"); // Matches parameter names like var1, var37
    
    private static final Map<String, String> FIELD_NAME_HINTS = new HashMap<>();
    private static final Map<String, String> METHOD_NAME_HINTS = new HashMap<>();
    
    static {
        // Field name hints based on type and usage patterns
        FIELD_NAME_HINTS.put("Ljava/lang/String;_c1", "prefixCommand");
        FIELD_NAME_HINTS.put("Ljava/util/Random;", "random");
        FIELD_NAME_HINTS.put("Ljava/util/concurrent/ScheduledExecutorService;_taext", "executorService");
        FIELD_NAME_HINTS.put("Lyo/zeru/Handler/Initializator;_cm", "commandManager");
        FIELD_NAME_HINTS.put("[Ljava/lang/String;_nothing_to_see_here", "asciiArt");
        
        // Method name hints based on signature and usage patterns
        METHOD_NAME_HINTS.put("()Lyo/zeru/Handler/Initializator;_gcm", "getCommandManager");
        METHOD_NAME_HINTS.put("(I)Ljava/lang/String;_gc", "getCommandPrefix");
        METHOD_NAME_HINTS.put("(I)Ljava/util/concurrent/ScheduledExecutorService;_asd", "getExecutorService");
        METHOD_NAME_HINTS.put("(I)Lyo/zeru/Main;_getInstance", "getInstance");
        METHOD_NAME_HINTS.put("(I)V_gengc", "generateCommandPrefix");
        METHOD_NAME_HINTS.put("()Ljava/lang/String;_get", "getRandomString");
    }
    
    @Override
    public void transform(ClassWrapper classWrapper) {
        // Create a mapping of old to new names for this class
        Map<String, String> fieldMappings = new HashMap<>();
        Map<String, String> methodMappings = new HashMap<>();
        int renamedFields = 0;
        int renamedMethods = 0;
        
        // First pass: rename fields
        for (FieldWrapper fieldWrapper : classWrapper.getFields()) {
            FieldNode fieldNode = fieldWrapper.getFieldNode();
            
            if (shouldRenameField(fieldNode)) {
                String newName = generateFieldName(classWrapper, fieldNode);
                fieldMappings.put(fieldNode.name, newName);
                fieldNode.name = newName;
                renamedFields++;
            }
        }
        
        // Second pass: rename methods
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            MethodNode methodNode = methodWrapper.getMethodNode();
            
            // Skip constructors and static initializers
            if (methodNode.name.equals("<init>") || methodNode.name.equals("<clinit>")) {
                continue;
            }
            
            if (shouldRenameMethod(methodNode)) {
                String newName = generateMethodName(classWrapper, methodNode);
                methodMappings.put(methodNode.name, newName);
                methodNode.name = newName;
                renamedMethods++;
            }
            
            // Rename local variables
            renameLocalVariables(methodNode);
        }
        
        // Apply the same renames to field and method references
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            MethodNode methodNode = methodWrapper.getMethodNode();
            
            // Update field references
            for (AbstractInsnNode insn : methodNode.instructions) {
                if (insn instanceof FieldInsnNode) {
                    FieldInsnNode fieldInsn = (FieldInsnNode) insn;
                    
                    // Only change fields in this class
                    if (fieldInsn.owner.equals(classWrapper.getName()) && 
                        fieldMappings.containsKey(fieldInsn.name)) {
                        fieldInsn.name = fieldMappings.get(fieldInsn.name);
                    }
                } else if (insn instanceof MethodInsnNode) {
                    MethodInsnNode methodInsn = (MethodInsnNode) insn;
                    
                    // Only change methods in this class
                    if (methodInsn.owner.equals(classWrapper.getName()) && 
                        methodMappings.containsKey(methodInsn.name) && 
                        !methodInsn.name.equals("<init>")) {
                        methodInsn.name = methodMappings.get(methodInsn.name);
                    }
                }
            }
        }
        
        if (renamedFields > 0 || renamedMethods > 0) {
            Run.log(classWrapper.getName() + " | Renamed " + renamedFields + 
                   " fields and " + renamedMethods + " methods");
        }
    }
    
    /**
     * Check if a field should be renamed
     */
    private boolean shouldRenameField(FieldNode fieldNode) {
        // Skip fields that already have meaningful names
        if (fieldNode.name.startsWith("this$") || 
            fieldNode.name.equals("serialVersionUID") || 
            fieldNode.name.equals("plugin") || 
            fieldNode.name.equals("instance")) {
            return false;
        }
        
        // Check if the field name matches obfuscated patterns
        return OBFUSCATED_FIELD_PATTERN.matcher(fieldNode.name).matches() || 
              fieldNode.name.length() <= 2 || // Very short names
              fieldNode.name.contains("$"); // Randomly generated names with $ sign
    }
    
    /**
     * Check if a method should be renamed
     */
    private boolean shouldRenameMethod(MethodNode methodNode) {
        // Skip methods that already have meaningful names
        if (methodNode.name.equals("onEnable") || 
            methodNode.name.equals("onCommand") || 
            methodNode.name.equals("toString") || 
            methodNode.name.equals("getName") || 
            methodNode.name.startsWith("get") || 
            methodNode.name.startsWith("set") || 
            methodNode.name.startsWith("is")) {
            return false;
        }
        
        // Check if the method name matches obfuscated patterns
        return OBFUSCATED_METHOD_PATTERN.matcher(methodNode.name).matches() || 
              methodNode.name.length() <= 2; // Very short names
    }
    
    /**
     * Generate a meaningful name for a field
     */
    private String generateFieldName(ClassWrapper classWrapper, FieldNode fieldNode) {
        // Check if we have a hint for this field type
        String key = fieldNode.desc;
        if (FIELD_NAME_HINTS.containsKey(key + "_" + fieldNode.name)) {
            return FIELD_NAME_HINTS.get(key + "_" + fieldNode.name);
        } else if (FIELD_NAME_HINTS.containsKey(key)) {
            return FIELD_NAME_HINTS.get(key);
        }
        
        // Generate name based on field type
        String typeName = getTypeBaseName(fieldNode.desc);
        
        // Check for arrays
        if (fieldNode.desc.startsWith("[")) {
            return typeName + "Array";
        }
        
        // Check if static
        if ((fieldNode.access & ACC_STATIC) != 0) {
            return "static" + capitalizeFirstLetter(typeName);
        }
        
        return typeName;
    }
    
    /**
     * Generate a meaningful name for a method
     */
    private String generateMethodName(ClassWrapper classWrapper, MethodNode methodNode) {
        // Check if we have a hint for this method signature
        String key = methodNode.desc + "_" + methodNode.name;
        if (METHOD_NAME_HINTS.containsKey(key)) {
            return METHOD_NAME_HINTS.get(key);
        }
        
        // Generate name based on return type and parameters
        Type returnType = Type.getReturnType(methodNode.desc);
        Type[] argTypes = Type.getArgumentTypes(methodNode.desc);
        
        // Check for common patterns
        if (returnType.getSort() == Type.VOID) {
            // Void methods often perform actions
            return "process" + (argTypes.length > 0 ? capitalizeFirstLetter(getTypeBaseName(argTypes[0].getDescriptor())) : "");
        } else {
            // Non-void methods often retrieve values
            return "get" + capitalizeFirstLetter(getTypeBaseName(returnType.getDescriptor()));
        }
    }
    
    /**
     * Rename local variables in a method
     */
    private void renameLocalVariables(MethodNode methodNode) {
        if (methodNode.localVariables == null) {
            return;
        }
        
        // Create a map of old index to new name
        Map<Integer, String> indexToName = new HashMap<>();
        int param = 0;
        
        // Check if this is a static method
        boolean isStatic = (methodNode.access & ACC_STATIC) != 0;
        
        // First local variable is 'this' for non-static methods
        if (!isStatic) {
            indexToName.put(0, "this");
            param = 1;
        }
        
        // Rename parameters first
        Type[] argTypes = Type.getArgumentTypes(methodNode.desc);
        for (int i = 0; i < argTypes.length; i++) {
            String name = "param" + (i + 1) + "_" + getTypeBaseName(argTypes[i].getDescriptor());
            indexToName.put(param, name);
            
            // Account for long and double parameters taking two slots
            if (argTypes[i].getSort() == Type.LONG || argTypes[i].getSort() == Type.DOUBLE) {
                param += 2;
            } else {
                param += 1;
            }
        }
        
        // Now rename all local variables
        for (LocalVariableNode lvn : methodNode.localVariables) {
            if (shouldRenameLocalVar(lvn)) {
                if (indexToName.containsKey(lvn.index)) {
                    lvn.name = indexToName.get(lvn.index);
                } else {
                    // For variables that aren't parameters
                    String name = "local" + lvn.index + "_" + getTypeBaseName(lvn.desc);
                    lvn.name = name;
                    indexToName.put(lvn.index, name);
                }
            }
        }
    }
    
    /**
     * Check if a local variable should be renamed
     */
    private boolean shouldRenameLocalVar(LocalVariableNode lvn) {
        if (lvn.name.equals("this")) {
            return false;
        }
        
        return OBFUSCATED_PARAM_PATTERN.matcher(lvn.name).matches() || 
              lvn.name.length() <= 2 || // Very short names
              lvn.name.matches("^[A-Z0-9]+$"); // All caps or numbers
    }
    
    /**
     * Get a base name for a type descriptor
     */
    private String getTypeBaseName(String desc) {
        switch (desc) {
            case "I":
                return "int";
            case "J":
                return "long";
            case "Z":
                return "boolean";
            case "F":
                return "float";
            case "D":
                return "double";
            case "B":
                return "byte";
            case "C":
                return "char";
            case "S":
                return "short";
            case "V":
                return "void";
            case "Ljava/lang/String;":
                return "string";
            case "Ljava/lang/Object;":
                return "object";
            case "Ljava/util/List;":
                return "list";
            case "Ljava/util/Map;":
                return "map";
            case "Lorg/bukkit/entity/Player;":
                return "player";
            case "Lorg/bukkit/plugin/java/JavaPlugin;":
                return "plugin";
            default:
                if (desc.startsWith("[")) {
                    return getTypeBaseName(desc.substring(1)) + "Array";
                } else if (desc.startsWith("L") && desc.endsWith(";")) {
                    // Extract class name from descriptor
                    String className = desc.substring(1, desc.length() - 1);
                    int lastSlash = className.lastIndexOf('/');
                    if (lastSlash >= 0) {
                        className = className.substring(lastSlash + 1);
                    }
                    
                    // Make first letter lowercase
                    if (!className.isEmpty()) {
                        className = Character.toLowerCase(className.charAt(0)) + 
                                   (className.length() > 1 ? className.substring(1) : "");
                    }
                    
                    return className;
                }
                return "unknown";
        }
    }
    
    /**
     * Capitalize the first letter of a string
     */
    private String capitalizeFirstLetter(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }
        return Character.toUpperCase(input.charAt(0)) + 
              (input.length() > 1 ? input.substring(1) : "");
    }
}