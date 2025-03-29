package dead.owner.deobf.transformers.colonial;

import dead.owner.deobf.Run;
import dead.owner.deobf.utils.wrapper.ClassWrapper;
import dead.owner.deobf.utils.wrapper.MethodWrapper;
import dead.owner.deobf.transformers.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Transformer to decrypt strings encrypted by Colonial Obfuscator.
 * Colonial typically uses a custom encryption method with keys stored in static fields.
 */
public class ColonialStringDecryptor implements Transformer, Opcodes {
    
    private static final Map<String, String> decryptionCache = new HashMap<>();
    
    // Common method names used for string decryption
    private static final String[] DECRYPT_METHOD_PATTERNS = {
        "decrypt", "unlock", "resolve", "getString", "getStringValue", "[a-zA-Z]{6,10}"
    };
    
    // Common field patterns used for encryption key storage
    private static final String[] KEY_FIELD_PATTERNS = {
        "key", "salt", "secret", "[a-zA-Z]{5,8}"
    };
    
    @Override
    public void transform(ClassWrapper classWrapper) {
        // Find potential string decryption methods
        List<MethodNode> decryptionMethods = findStringDecryptionMethods(classWrapper);
        if (decryptionMethods.isEmpty()) {
            return;
        }
        
        // Find potential key fields
        Map<String, FieldNode> keyFields = findKeyFields(classWrapper);
        
        // Process each method to find and replace encrypted strings
        int decryptedCount = 0;
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            // Skip the decryption methods themselves
            if (decryptionMethods.contains(methodWrapper.getMethodNode())) {
                continue;
            }
            
            decryptedCount += decryptStringsInMethod(classWrapper, methodWrapper, decryptionMethods, keyFields);
        }
        
        // Remove the decryption methods if we found encrypted strings
        if (decryptedCount > 0) {
            for (MethodNode decryptionMethod : decryptionMethods) {
                classWrapper.getMethodsAsNodes().remove(decryptionMethod);
            }
            
            // Remove key fields
            for (FieldNode keyField : keyFields.values()) {
                classWrapper.getFieldsAsNodes().remove(keyField);
            }
            
            Run.log(classWrapper.getName() + " | Decrypted " + decryptedCount + " Colonial strings");
        }
    }
    
    /**
     * Find methods that appear to be string decryption methods
     */
    private List<MethodNode> findStringDecryptionMethods(ClassWrapper classWrapper) {
        List<MethodNode> result = new ArrayList<>();
        
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            MethodNode methodNode = methodWrapper.getMethodNode();
            
            // Check return type - should return String
            if (!Type.getReturnType(methodNode.desc).getDescriptor().equals("Ljava/lang/String;")) {
                continue;
            }
            
            // Check for method name patterns
            for (String pattern : DECRYPT_METHOD_PATTERNS) {
                if (methodNode.name.matches(pattern)) {
                    result.add(methodNode);
                    break;
                }
            }
            
            // Check parameter patterns
            Type[] paramTypes = Type.getArgumentTypes(methodNode.desc);
            if (paramTypes.length == 1 && 
               (paramTypes[0].getDescriptor().equals("Ljava/lang/String;") ||
                paramTypes[0].getDescriptor().equals("[B") ||
                paramTypes[0].getDescriptor().equals("I"))) {
                result.add(methodNode);
                continue;
            }
            
            // Check method body for common decryption patterns
            if (containsDecryptionPattern(methodNode)) {
                result.add(methodNode);
            }
        }
        
        return result;
    }
    
    /**
     * Find fields that may store encryption keys
     */
    private Map<String, FieldNode> findKeyFields(ClassWrapper classWrapper) {
        Map<String, FieldNode> result = new HashMap<>();
        
        for (FieldNode fieldNode : classWrapper.getFieldsAsNodes()) {
            // Look for static fields with appropriate types
            if ((fieldNode.access & ACC_STATIC) != 0) {
                if (fieldNode.desc.equals("[B") || fieldNode.desc.equals("[C") || 
                    fieldNode.desc.equals("Ljava/lang/String;") || 
                    fieldNode.desc.equals("I")) {
                    
                    // Check for field name patterns
                    for (String pattern : KEY_FIELD_PATTERNS) {
                        if (fieldNode.name.matches(pattern)) {
                            result.put(fieldNode.name, fieldNode);
                            break;
                        }
                    }
                }
            }
        }
        
        return result;
    }
    
    /**
     * Check if a method contains common string decryption patterns
     */
    private boolean containsDecryptionPattern(MethodNode methodNode) {
        boolean hasStringManipulation = false;
        boolean hasEncryptionOps = false;
        
        for (AbstractInsnNode insn : methodNode.instructions) {
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                
                // Check for string manipulation methods
                if (methodInsn.owner.equals("java/lang/String") && 
                   (methodInsn.name.equals("toCharArray") || 
                    methodInsn.name.equals("getBytes") || 
                    methodInsn.name.equals("charAt") ||
                    methodInsn.name.equals("valueOf"))) {
                    hasStringManipulation = true;
                }
                
                // Check for common encryption/decryption methods
                if ((methodInsn.owner.equals("javax/crypto/Cipher") && 
                    (methodInsn.name.equals("getInstance") || 
                     methodInsn.name.equals("init") || 
                     methodInsn.name.equals("doFinal"))) || 
                    (methodInsn.owner.equals("java/util/Base64") && 
                     methodInsn.name.contains("decode"))) {
                    hasEncryptionOps = true;
                }
            }
            
            // Check for XOR operations (common in simple decryption)
            if (insn.getOpcode() == IXOR || insn.getOpcode() == LXOR) {
                hasEncryptionOps = true;
            }
        }
        
        return hasStringManipulation && hasEncryptionOps;
    }
    
    /**
     * Decrypt strings in a method
     */
    private int decryptStringsInMethod(ClassWrapper classWrapper, MethodWrapper methodWrapper, 
                                    List<MethodNode> decryptionMethods, Map<String, FieldNode> keyFields) {
        MethodNode methodNode = methodWrapper.getMethodNode();
        int count = 0;
        
        // Look for calls to decryption methods
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Store next before potential modification
            
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                
                // Check if this is a call to one of our identified decryption methods
                for (MethodNode decryptionMethod : decryptionMethods) {
                    if (methodInsn.owner.equals(classWrapper.getName()) && 
                        methodInsn.name.equals(decryptionMethod.name) && 
                        methodInsn.desc.equals(decryptionMethod.desc)) {
                        
                        // Try to decrypt the string
                        if (tryDecryptStringCall(classWrapper, methodNode, insn, decryptionMethod, keyFields)) {
                            count++;
                        }
                        break;
                    }
                }
            }
            
            insn = next;
        }
        
        return count;
    }
    
    /**
     * Try to decrypt a string decryption method call
     */
    private boolean tryDecryptStringCall(ClassWrapper classWrapper, MethodNode methodNode, 
                                       AbstractInsnNode callInsn, MethodNode decryptionMethod,
                                       Map<String, FieldNode> keyFields) {
        if (!(callInsn instanceof MethodInsnNode)) {
            return false;
        }
        
        MethodInsnNode methodInsn = (MethodInsnNode) callInsn;
        
        // Extract arguments to the decryption method
        List<AbstractInsnNode> args = findArguments(methodNode, callInsn);
        if (args.isEmpty()) {
            return false;
        }
        
        // Create a cache key for this call
        String cacheKey = methodInsn.owner + "." + methodInsn.name + ":" + createArgHash(args);
        
        // Check if we've already decrypted this string
        if (decryptionCache.containsKey(cacheKey)) {
            // Replace with the cached result
            LdcInsnNode ldcInsn = new LdcInsnNode(decryptionCache.get(cacheKey));
            methodNode.instructions.insertBefore(callInsn, ldcInsn);
            
            // Remove the method call and its arguments
            removeInstructions(methodNode, args, callInsn);
            return true;
        }
        
        // Try different decryption strategies
        String decrypted = tryDecryptString(classWrapper, args, decryptionMethod, keyFields);
        
        if (decrypted != null) {
            // Cache the result
            decryptionCache.put(cacheKey, decrypted);
            
            // Replace the method call with the decrypted string
            LdcInsnNode ldcInsn = new LdcInsnNode(decrypted);
            methodNode.instructions.insertBefore(callInsn, ldcInsn);
            
            // Remove the method call and its arguments
            removeInstructions(methodNode, args, callInsn);
            return true;
        }
        
        return false;
    }
    
    /**
     * Try various string decryption strategies
     */
    private String tryDecryptString(ClassWrapper classWrapper, List<AbstractInsnNode> args, 
                                 MethodNode decryptionMethod, Map<String, FieldNode> keyFields) {
        // Try to determine which decryption method is used by analyzing the method body
        boolean usesXor = false;
        boolean usesAes = false;
        boolean usesBase64 = false;
        
        for (AbstractInsnNode insn : decryptionMethod.instructions) {
            if (insn.getOpcode() == IXOR) {
                usesXor = true;
            } else if (insn instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                if (methodInsn.owner.equals("javax/crypto/Cipher")) {
                    usesAes = true;
                } else if (methodInsn.owner.equals("java/util/Base64")) {
                    usesBase64 = true;
                }
            }
        }
        
        // Extract information from arguments
        String encrypted = extractStringValue(args);
        byte[] encryptedBytes = extractByteArray(args);
        Integer key = extractIntValue(args);
        
        // Try different decryption strategies
        
        // Strategy 1: Simple XOR decryption
        if (usesXor && encrypted != null && key != null) {
            String xorResult = tryXorDecrypt(encrypted, key);
            if (xorResult != null && isLikelyValidString(xorResult)) {
                return xorResult;
            }
        }
        
        // Strategy 2: Base64 + XOR decryption
        if (usesBase64 && usesXor && encrypted != null) {
            // Find a key from the key fields if not provided in args
            if (key == null) {
                key = extractKeyFromField(keyFields);
            }
            
            if (key != null) {
                String base64XorResult = tryBase64XorDecrypt(encrypted, key);
                if (base64XorResult != null && isLikelyValidString(base64XorResult)) {
                    return base64XorResult;
                }
            }
        }
        
        // Strategy 3: AES decryption
        if (usesAes && encryptedBytes != null) {
            byte[] keyBytes = extractKeyBytes(keyFields);
            if (keyBytes != null) {
                String aesResult = tryAesDecrypt(encryptedBytes, keyBytes);
                if (aesResult != null && isLikelyValidString(aesResult)) {
                    return aesResult;
                }
            }
        }
        
        // Strategy 4: Custom character manipulation (common in Colonial)
        if (encrypted != null) {
            String customResult = tryCustomDecrypt(encrypted, key);
            if (customResult != null && isLikelyValidString(customResult)) {
                return customResult;
            }
        }
        
        return null;
    }
    
    /**
     * Try to decrypt a string using XOR
     */
    private String tryXorDecrypt(String input, int key) {
        try {
            char[] chars = input.toCharArray();
            for (int i = 0; i < chars.length; i++) {
                chars[i] = (char) (chars[i] ^ key);
            }
            return new String(chars);
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * Try to decrypt a string using Base64 + XOR
     */
    private String tryBase64XorDecrypt(String input, int key) {
        try {
            byte[] decoded = Base64.getDecoder().decode(input);
            for (int i = 0; i < decoded.length; i++) {
                decoded[i] = (byte) (decoded[i] ^ key);
            }
            return new String(decoded, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * Try to decrypt a string using AES
     */
    private String tryAesDecrypt(byte[] encryptedBytes, byte[] keyBytes) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decrypted = cipher.doFinal(encryptedBytes);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * Try to decrypt a string using custom character manipulation
     */
    private String tryCustomDecrypt(String input, Integer key) {
        if (key == null) {
            // Try some common keys
            for (int k : new int[] {0xDEAD, 0xBEEF, 0xCAFE, 0xBABE, 0x1337, 42, 13}) {
                String result = tryXorDecrypt(input, k);
                if (result != null && isLikelyValidString(result)) {
                    return result;
                }
            }
        } else {
            // Try character rotation (common in Colonial)
            try {
                char[] chars = input.toCharArray();
                for (int i = 0; i < chars.length; i++) {
                    chars[i] = (char) (chars[i] - key);
                }
                return new String(chars);
            } catch (Exception e) {
                // Ignore errors
            }
        }
        
        return null;
    }
    
    /**
     * Extract a key from static fields
     */
    private Integer extractKeyFromField(Map<String, FieldNode> keyFields) {
        for (FieldNode field : keyFields.values()) {
            if (field.desc.equals("I")) {
                // This is an integer field - could be a key
                // We can't easily determine its value without more complex analysis
                return 0xDEAD; // Use a default value
            }
        }
        
        return null;
    }
    
    /**
     * Extract key bytes from static fields
     */
    private byte[] extractKeyBytes(Map<String, FieldNode> keyFields) {
        for (FieldNode field : keyFields.values()) {
            if (field.desc.equals("[B")) {
                // This is a byte array field - could be a key
                // We can't easily determine its value without more complex analysis
                return new byte[] {
                    (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF,
                    (byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE,
                    (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF,
                    (byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE
                }; // Use a default key
            }
        }
        
        return null;
    }
    
    /**
     * Extract a string value from arguments
     */
    private String extractStringValue(List<AbstractInsnNode> args) {
        for (AbstractInsnNode arg : args) {
            if (arg instanceof LdcInsnNode && ((LdcInsnNode) arg).cst instanceof String) {
                return (String) ((LdcInsnNode) arg).cst;
            }
        }
        
        return null;
    }
    
    /**
     * Extract a byte array from arguments
     */
    private byte[] extractByteArray(List<AbstractInsnNode> args) {
        String stringValue = extractStringValue(args);
        if (stringValue != null) {
            return stringValue.getBytes(StandardCharsets.UTF_8);
        }
        
        return null;
    }
    
    /**
     * Extract an integer value from arguments
     */
    private Integer extractIntValue(List<AbstractInsnNode> args) {
        for (AbstractInsnNode arg : args) {
            if (arg instanceof IntInsnNode) {
                return ((IntInsnNode) arg).operand;
            } else if (arg instanceof LdcInsnNode && ((LdcInsnNode) arg).cst instanceof Integer) {
                return (Integer) ((LdcInsnNode) arg).cst;
            } else if (arg.getOpcode() >= ICONST_0 && arg.getOpcode() <= ICONST_5) {
                return arg.getOpcode() - ICONST_0;
            } else if (arg.getOpcode() == ICONST_M1) {
                return -1;
            }
        }
        
        return null;
    }
    
    /**
     * Find the arguments to a method call
     */
    private List<AbstractInsnNode> findArguments(MethodNode methodNode, AbstractInsnNode callInsn) {
        if (!(callInsn instanceof MethodInsnNode)) {
            return Collections.emptyList();
        }
        
        MethodInsnNode methodInsn = (MethodInsnNode) callInsn;
        Type[] argTypes = Type.getArgumentTypes(methodInsn.desc);
        if (argTypes.length == 0) {
            return Collections.emptyList();
        }
        
        List<AbstractInsnNode> args = new ArrayList<>();
        AbstractInsnNode current = callInsn.getPrevious();
        
        // Simple heuristic - take the N previous non-label instructions as arguments
        int argsFound = 0;
        while (current != null && argsFound < argTypes.length) {
            if (!(current instanceof LabelNode) && 
                !(current instanceof LineNumberNode) && 
                !(current instanceof FrameNode)) {
                args.add(0, current);
                argsFound++;
            }
            current = current.getPrevious();
        }
        
        return args;
    }
    
    /**
     * Create a hash for caching based on method arguments
     */
    private String createArgHash(List<AbstractInsnNode> args) {
        StringBuilder sb = new StringBuilder();
        for (AbstractInsnNode arg : args) {
            if (arg instanceof LdcInsnNode) {
                sb.append(((LdcInsnNode) arg).cst);
            } else if (arg instanceof IntInsnNode) {
                sb.append(((IntInsnNode) arg).operand);
            } else if (arg.getOpcode() >= ICONST_0 && arg.getOpcode() <= ICONST_5) {
                sb.append(arg.getOpcode() - ICONST_0);
            } else if (arg.getOpcode() == ICONST_M1) {
                sb.append("-1");
            } else if (arg instanceof MethodInsnNode) {
                sb.append(((MethodInsnNode) arg).name);
            }
            sb.append(":");
        }
        return sb.toString();
    }
    
    /**
     * Remove a method call and its arguments from the instruction list
     */
    private void removeInstructions(MethodNode methodNode, List<AbstractInsnNode> args, AbstractInsnNode callInsn) {
        methodNode.instructions.remove(callInsn);
        for (AbstractInsnNode arg : args) {
            methodNode.instructions.remove(arg);
        }
    }
    
    /**
     * Check if a string is likely valid (not garbage)
     */
    private boolean isLikelyValidString(String str) {
        if (str == null || str.isEmpty()) {
            return false;
        }
        
        // Check if the string contains mostly printable ASCII
        int printableCount = 0;
        for (char c : str.toCharArray()) {
            if (c >= 32 && c <= 126) {
                printableCount++;
            }
        }
        
        return printableCount > str.length() * 0.7;
    }
}