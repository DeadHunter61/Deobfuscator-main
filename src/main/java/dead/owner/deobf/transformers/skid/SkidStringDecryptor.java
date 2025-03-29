package dead.owner.deobf.transformers.skid;

import dead.owner.deobf.Run;
import dead.owner.deobf.utils.wrapper.ClassWrapper;
import dead.owner.deobf.utils.wrapper.MethodWrapper;
import dead.owner.deobf.transformers.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Transformer to decrypt strings encrypted by SkidFuscator
 */
public class SkidStringDecryptor implements Transformer, Opcodes {
    private static final Map<String, String> decryptionCache = new HashMap<>();
    
    // Common method names and patterns used in SkidFuscator for string decryption
    private static final String[] DECRYPT_METHOD_PATTERNS = {
        "decrypt", "decode", "getStringFromBytes"
    };
    
    // Field name patterns for encrypted string storage
    private static final String[] ENCRYPTED_FIELD_PATTERNS = {
        "nothing_to_see_here", "[a-z]{10,}"
    };
    
    @Override
    public void transform(ClassWrapper classWrapper) {
        // Find possible string decryption methods
        List<MethodNode> decryptionMethods = findStringDecryptionMethods(classWrapper);
        if (decryptionMethods.isEmpty()) {
            return;
        }
        
        // Find possible static byte array fields used for decryption
        Map<String, FieldNode> decryptionFields = findDecryptionFields(classWrapper);
        
        // Process each method to find and replace encrypted strings
        int decryptedCount = 0;
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            // Skip the decryption methods themselves
            if (decryptionMethods.contains(methodWrapper.getMethodNode())) {
                continue;
            }
            
            decryptedCount += decryptStringsInMethod(classWrapper, methodWrapper, decryptionMethods, decryptionFields);
        }
        
        // Remove decryption methods if we found encrypted strings
        if (decryptedCount > 0) {
            for (MethodNode decryptionMethod : decryptionMethods) {
                classWrapper.getMethodsAsNodes().remove(decryptionMethod);
            }
            
            Run.log(classWrapper.getName() + " | Decrypted " + decryptedCount + " SkidFuscator strings");
        }
    }
    
    /**
     * Find methods that appear to be string decryption methods used by SkidFuscator
     */
    private List<MethodNode> findStringDecryptionMethods(ClassWrapper classWrapper) {
        List<MethodNode> result = new ArrayList<>();
        
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            MethodNode methodNode = methodWrapper.getMethodNode();
            
            // Check for common return types of decryption methods
            Type returnType = Type.getReturnType(methodNode.desc);
            if (returnType.getDescriptor().equals("Ljava/lang/String;") || 
                returnType.getDescriptor().equals("[B")) {
                
                // Check for method name patterns
                for (String pattern : DECRYPT_METHOD_PATTERNS) {
                    if (methodNode.name.matches(pattern)) {
                        result.add(methodNode);
                        break;
                    }
                }
                
                // Check for methods that take byte arrays and an integer (common in SkidFuscator)
                if (methodNode.desc.startsWith("([BI)")) {
                    result.add(methodNode);
                }
                
                // Check for other common patterns
                if (containsDecryptionPattern(methodNode)) {
                    result.add(methodNode);
                }
            }
        }
        
        return result;
    }
    
    /**
     * Find fields that may store encrypted strings or decryption keys
     */
    private Map<String, FieldNode> findDecryptionFields(ClassWrapper classWrapper) {
        Map<String, FieldNode> result = new HashMap<>();
        
        for (FieldNode fieldNode : classWrapper.getFieldsAsNodes()) {
            // Look for static byte array fields
            if ((fieldNode.access & ACC_STATIC) != 0) {
                if (fieldNode.desc.equals("[B") || fieldNode.desc.equals("[C") || 
                    fieldNode.desc.equals("Ljava/lang/String;")) {
                    
                    // Check for field name patterns
                    for (String pattern : ENCRYPTED_FIELD_PATTERNS) {
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
        for (AbstractInsnNode insn : methodNode.instructions) {
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                
                // Common operations in SkidFuscator decryption methods
                if (methodInsn.owner.equals("java/lang/String") && 
                   (methodInsn.name.equals("getBytes") || methodInsn.name.equals("valueOf"))) {
                    return true;
                }
                
                // ByteBuffer operations (SkidFuscator often uses ByteBuffer)
                if (methodInsn.owner.equals("java/nio/ByteBuffer") && 
                   (methodInsn.name.equals("wrap") || methodInsn.name.equals("allocate"))) {
                    return true;
                }
                
                // Base64 decoding (sometimes used)
                if (methodInsn.owner.equals("java/util/Base64") && 
                    methodInsn.name.contains("decode")) {
                    return true;
                }
            }
            
            // XOR operations are common in decryption
            if (insn.getOpcode() == IXOR) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Decrypt strings in a method
     */
    private int decryptStringsInMethod(ClassWrapper classWrapper, MethodWrapper methodWrapper, 
                                     List<MethodNode> decryptionMethods, Map<String, FieldNode> decryptionFields) {
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
                        if (tryDecryptStringCall(classWrapper, methodNode, insn)) {
                            count++;
                        }
                        break;
                    }
                }
            }
            
            // Also check for SkidFuscator's specific pattern with SDK calls
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                if (methodInsn.owner.equals("sdk/SDK") && 
                    (methodInsn.name.equals("decrypt") || methodInsn.name.equals("checkType") || 
                     methodInsn.name.equals("hash"))) {
                    
                    // Try to handle SDK-based decryption
                    if (tryDecryptSdkCall(classWrapper, methodNode, insn)) {
                        count++;
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
    private boolean tryDecryptStringCall(ClassWrapper classWrapper, MethodNode methodNode, AbstractInsnNode callInsn) {
        if (!(callInsn instanceof MethodInsnNode)) {
            return false;
        }
        
        MethodInsnNode methodInsn = (MethodInsnNode) callInsn;
        
        // Try to extract the arguments
        List<AbstractInsnNode> args = findArguments(methodNode, callInsn);
        if (args.isEmpty()) {
            return false;
        }
        
        // Try various decryption strategies based on the pattern
        String decrypted = null;
        
        // First check if we have a cached result
        String cacheKey = methodInsn.owner + "." + methodInsn.name + ":" + createArgHash(args);
        if (decryptionCache.containsKey(cacheKey)) {
            decrypted = decryptionCache.get(cacheKey);
        } else {
            // Try different decryption strategies
            decrypted = tryDecryptStrategies(classWrapper, args, methodInsn);
            
            if (decrypted != null) {
                decryptionCache.put(cacheKey, decrypted);
            }
        }
        
        if (decrypted != null) {
            // Replace the method call with the constant string
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
    private String tryDecryptStrategies(ClassWrapper classWrapper, List<AbstractInsnNode> args, MethodInsnNode methodInsn) {
        // Strategy 1: ByteBuffer decrypt - common in SkidFuscator
        String byteBufferResult = tryByteBufferDecrypt(args);
        if (byteBufferResult != null) {
            return byteBufferResult;
        }
        
        // Strategy 2: XOR decrypt - common in SkidFuscator
        String xorResult = tryXorDecrypt(args);
        if (xorResult != null) {
            return xorResult;
        }
        
        // Strategy 3: Base64 decrypt
        String base64Result = tryBase64Decrypt(args);
        if (base64Result != null) {
            return base64Result;
        }
        
        return null;
    }
    
    /**
     * Try to decrypt a string using ByteBuffer (common in SkidFuscator)
     */
    private String tryByteBufferDecrypt(List<AbstractInsnNode> args) {
        // Extract byte array from arguments if possible
        byte[] data = extractByteArray(args);
        if (data == null || data.length == 0) {
            return null;
        }
        
        try {
            // Try UTF-8 decoding
            String utf8Result = new String(data, StandardCharsets.UTF_8);
            if (isLikelyValidString(utf8Result)) {
                return utf8Result;
            }
            
            // Try UTF-16 decoding
            String utf16Result = new String(data, StandardCharsets.UTF_16);
            if (isLikelyValidString(utf16Result)) {
                return utf16Result;
            }
            
            // Try as ByteBuffer to CharBuffer conversion
            if (data.length % 2 == 0) {
                ByteBuffer buffer = ByteBuffer.wrap(data);
                String charBufferResult = StandardCharsets.UTF_16LE.decode(buffer).toString();
                if (isLikelyValidString(charBufferResult)) {
                    return charBufferResult;
                }
            }
        } catch (Exception e) {
            // Ignore decryption errors
        }
        
        return null;
    }
    
    /**
     * Try to decrypt a string using XOR (common in SkidFuscator)
     */
    private String tryXorDecrypt(List<AbstractInsnNode> args) {
        // Extract byte array and key from arguments if possible
        byte[] data = extractByteArray(args);
        if (data == null || data.length == 0) {
            return null;
        }
        
        // Try to find an integer key argument
        Integer key = extractIntValue(args);
        if (key == null) {
            key = 0; // Default key if not found
        }
        
        try {
            // Perform XOR decryption with the key
            byte[] result = new byte[data.length];
            for (int i = 0; i < data.length; i++) {
                result[i] = (byte)(data[i] ^ (key & 0xFF));
            }
            
            // Try different encodings
            String utf8Result = new String(result, StandardCharsets.UTF_8);
            if (isLikelyValidString(utf8Result)) {
                return utf8Result;
            }
            
            String utf16Result = new String(result, StandardCharsets.UTF_16);
            if (isLikelyValidString(utf16Result)) {
                return utf16Result;
            }
        } catch (Exception e) {
            // Ignore decryption errors
        }
        
        return null;
    }
    
    /**
     * Try to decrypt a string using Base64
     */
    private String tryBase64Decrypt(List<AbstractInsnNode> args) {
        // Extract string from arguments if possible
        String base64 = extractStringValue(args);
        if (base64 == null || base64.isEmpty()) {
            return null;
        }
        
        try {
            // Try Base64 decoding
            byte[] decoded = Base64.getDecoder().decode(base64);
            String result = new String(decoded, StandardCharsets.UTF_8);
            if (isLikelyValidString(result)) {
                return result;
            }
        } catch (Exception e) {
            // Ignore decryption errors
        }
        
        return null;
    }
    
    /**
     * Try to decrypt an SDK call (specific to SkidFuscator)
     */
    private boolean tryDecryptSdkCall(ClassWrapper classWrapper, MethodNode methodNode, AbstractInsnNode callInsn) {
        if (!(callInsn instanceof MethodInsnNode)) {
            return false;
        }
        
        MethodInsnNode methodInsn = (MethodInsnNode) callInsn;
        
        // Handle different SDK methods
        switch (methodInsn.name) {
            case "hash":
                return handleSdkHashCall(classWrapper, methodNode, methodInsn);
                
            case "checkType":
                return handleSdkCheckTypeCall(classWrapper, methodNode, methodInsn);
                
            case "decrypt":
                return handleSdkDecryptCall(classWrapper, methodNode, methodInsn);
                
            default:
                return false;
        }
    }
    
    /**
     * Handle SDK.hash() call (used for string comparison obfuscation)
     */
    private boolean handleSdkHashCall(ClassWrapper classWrapper, MethodNode methodNode, MethodInsnNode methodInsn) {
        // SDK.hash() typically takes a string and returns a hashed version
        // We can just remove it if it's used for string equality
        
        AbstractInsnNode next = methodInsn.getNext();
        if (next instanceof MethodInsnNode) {
            MethodInsnNode nextMethod = (MethodInsnNode) next;
            if (nextMethod.owner.equals("java/lang/String") && nextMethod.name.equals("equals")) {
                // This is likely the string equality pattern
                // Remove the hash call and let the strings be compared directly
                methodNode.instructions.remove(methodInsn);
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Handle SDK.checkType() call (used for instanceof obfuscation)
     */
    private boolean handleSdkCheckTypeCall(ClassWrapper classWrapper, MethodNode methodNode, MethodInsnNode methodInsn) {
        // SDK.checkType() typically takes an object, a type hash, and a key
        // We can try to replace it with a direct instanceof check
        
        // This is more complex and would require knowing the original type
        // For now, we'll leave it untouched
        return false;
    }
    
    /**
     * Handle SDK.decrypt() call (direct string decryption)
     */
    private boolean handleSdkDecryptCall(ClassWrapper classWrapper, MethodNode methodNode, MethodInsnNode methodInsn) {
        // Extract the arguments to the decrypt call
        List<AbstractInsnNode> args = findArguments(methodNode, methodInsn);
        if (args.size() < 2) {
            return false;
        }
        
        // Try to extract the encrypted string and key
        String encrypted = extractStringValue(args);
        Integer key = extractIntValue(args);
        
        if (encrypted != null && key != null) {
            // Try to decrypt using XOR
            try {
                byte[] bytes = encrypted.getBytes(StandardCharsets.UTF_8);
                byte[] result = new byte[bytes.length];
                for (int i = 0; i < bytes.length; i++) {
                    result[i] = (byte)(bytes[i] ^ (key & 0xFF));
                }
                
                String decrypted = new String(result, StandardCharsets.UTF_8);
                if (isLikelyValidString(decrypted)) {
                    // Replace with decrypted string
                    LdcInsnNode ldcInsn = new LdcInsnNode(decrypted);
                    methodNode.instructions.insertBefore(methodInsn, ldcInsn);
                    
                    // Remove the method call and its arguments
                    removeInstructions(methodNode, args, methodInsn);
                    return true;
                }
            } catch (Exception e) {
                // Ignore decryption errors
            }
        }
        
        return false;
    }
    
    /**
     * Extract a byte array from arguments
     */
    private byte[] extractByteArray(List<AbstractInsnNode> args) {
        for (AbstractInsnNode arg : args) {
            if (arg instanceof MethodInsnNode) {
                MethodInsnNode methodArg = (MethodInsnNode) arg;
                if (methodArg.desc.equals("()[B")) {
                    // This is a method returning byte[]
                    // We can't easily extract the actual bytes without more complex analysis
                    return new byte[0];
                }
            } else if (arg instanceof LdcInsnNode) {
                LdcInsnNode ldcArg = (LdcInsnNode) arg;
                if (ldcArg.cst instanceof String) {
                    return ((String) ldcArg.cst).getBytes(StandardCharsets.UTF_8);
                }
            }
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
        // This is not 100% accurate but works for most cases
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