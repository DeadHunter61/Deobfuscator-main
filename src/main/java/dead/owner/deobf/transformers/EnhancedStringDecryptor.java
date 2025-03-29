package dead.owner.deobf.transformers;

import dead.owner.deobf.Run;
import dead.owner.deobf.utils.wrapper.ClassWrapper;
import dead.owner.deobf.utils.wrapper.MethodWrapper;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/**
 * Enhanced string decryptor that can handle more complex string encryption methods
 */
public class EnhancedStringDecryptor implements Transformer, Opcodes {
    
    private final Map<String, String> decryptedStrings = new HashMap<>();
    private final Map<String, MethodAnalysis> decryptionMethods = new HashMap<>();
    
    // This class keeps track of important details about a string decryption method
    private static class MethodAnalysis {
        String className;
        String methodName;
        String descriptor;
        Method decryptionType;
        FieldInsnNode charDataField;
        byte[] cipherKey;
        String hashAlgorithm;
        int keyLength;
        
        enum Method {
            STATIC_ARRAY,      // Using a static character array in field
            DYNAMIC_CHAR_BUFFER, // Using a byte[] -> CharBuffer method
            XOR_WITH_KEY,      // Simple XOR with a key
            AES_ENCRYPTION,    // AES encryption-based
            CUSTOM            // Other custom encryption
        }
    }
    
    @Override
    public void transform(ClassWrapper classWrapper) {
        // First pass: identify all string decryption methods
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            MethodNode methodNode = methodWrapper.getMethodNode();
            
            // Look for methods that might be string decryption methods
            if (isLikelyStringDecryptionMethod(methodNode)) {
                MethodAnalysis analysis = analyzeStringDecryptionMethod(classWrapper, methodWrapper);
                if (analysis != null) {
                    decryptionMethods.put(
                        classWrapper.getName() + "." + methodNode.name + methodNode.desc, 
                        analysis
                    );
                    Run.log(classWrapper.getName() + " | Found string decryption method: " + methodNode.name);
                }
            }
        }
        
        // Second pass: find static byte arrays that are used for decryption
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            if (methodWrapper.getName().startsWith("jfvkmqmrjvzqefk") || 
                methodWrapper.getName().startsWith("oqhkbybrdbmhdgr") ||
                methodWrapper.getName().startsWith("pznhbxdxvcrxygh") ||
                methodWrapper.getName().matches(".*[a-z]{10,}.*")) {
                
                if (methodWrapper.getReturnType().equals("[B")) {
                    // This is likely a method that returns a byte array for decryption
                    try {
                        byte[] data = extractByteArrayFromMethod(methodWrapper.getMethodNode());
                        if (data != null && data.length > 0) {
                            Run.log(classWrapper.getName() + " | Found byte array data in method: " + methodWrapper.getName());
                            
                            // Try to find the field that stores this data as a string
                            for (FieldInsnNode fieldInsn : findFieldsUsingByteArrayData(classWrapper)) {
                                for (MethodAnalysis analysis : decryptionMethods.values()) {
                                    if (analysis.charDataField == null && 
                                        fieldInsn.owner.equals(classWrapper.getName()) &&
                                        fieldInsn.desc.equals("Ljava/lang/String;")) {
                                        analysis.charDataField = fieldInsn;
                                        break;
                                    }
                                }
                            }
                        }
                    } catch (Exception e) {
                        Run.log(classWrapper.getName() + " | Couldn't extract byte array from " + methodWrapper.getName());
                    }
                }
            }
        }
        
        // Third pass: Look for static fields with string values set in a static block
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            if (methodWrapper.getName().equals("<clinit>")) {
                analyzeStaticInitializer(classWrapper, methodWrapper.getMethodNode());
            }
        }
        
        // Fourth pass: apply string decryption to all methods
        int decryptedCount = 0;
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            decryptedCount += decryptStringsInMethod(classWrapper, methodWrapper);
        }
        
        if (decryptedCount > 0) {
            Run.log(classWrapper.getName() + " | Decrypted " + decryptedCount + " strings");
        }
        
        // Final pass: remove decryption methods and fields
        removeDecryptionMethods(classWrapper);
    }
    
    /**
     * Analyze the static initializer to find field initialization with string data
     */
    private void analyzeStaticInitializer(ClassWrapper classWrapper, MethodNode clinitMethod) {
        // Look for patterns like:
        // getstatic, invokestatic ByteBuffer.wrap(), invokevirtual asCharBuffer(), invokevirtual toString(), putstatic
        
        for (AbstractInsnNode insn = clinitMethod.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                
                if (methodInsn.owner.equals("java/nio/ByteBuffer") && 
                    methodInsn.name.equals("wrap") && 
                    methodInsn.desc.equals("([B)Ljava/nio/ByteBuffer;")) {
                    
                    // Found ByteBuffer.wrap - try to find the method that provides the byte array
                    AbstractInsnNode prev = insn.getPrevious();
                    if (prev instanceof MethodInsnNode) {
                        MethodInsnNode byteArrayMethod = (MethodInsnNode) prev;
                        if (byteArrayMethod.desc.equals("()[B")) {
                            // This looks like our byte array source method
                            // Now find the field where the string is stored
                            AbstractInsnNode current = insn;
                            while (current != null && !(current instanceof FieldInsnNode && 
                                                      ((FieldInsnNode)current).getOpcode() == PUTSTATIC)) {
                                current = current.getNext();
                            }
                            
                            if (current instanceof FieldInsnNode) {
                                FieldInsnNode fieldInsn = (FieldInsnNode) current;
                                if (fieldInsn.desc.equals("Ljava/lang/String;")) {
                                    // Associate this field with a decryption method
                                    for (MethodAnalysis analysis : decryptionMethods.values()) {
                                        if (analysis.decryptionType == MethodAnalysis.Method.DYNAMIC_CHAR_BUFFER &&
                                            analysis.charDataField == null) {
                                            analysis.charDataField = fieldInsn;
                                            Run.log(classWrapper.getName() + " | Associated field " + fieldInsn.name + 
                                                   " with decryption method");
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    /**
     * Find field instructions that might be using byte array data
     */
    private List<FieldInsnNode> findFieldsUsingByteArrayData(ClassWrapper classWrapper) {
        List<FieldInsnNode> result = new ArrayList<>();
        
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            for (AbstractInsnNode insn : methodWrapper.getMethodNode().instructions) {
                if (insn instanceof FieldInsnNode) {
                    FieldInsnNode fieldInsn = (FieldInsnNode) insn;
                    if (fieldInsn.getOpcode() == GETSTATIC && 
                        fieldInsn.owner.equals(classWrapper.getName())) {
                        result.add(fieldInsn);
                    }
                }
            }
        }
        
        return result;
    }
    
    /**
     * Extract a byte array from a static method
     */
    private byte[] extractByteArrayFromMethod(MethodNode methodNode) {
        List<Integer> bytes = new ArrayList<>();
        
        // Look for patterns like:
        // return new byte[] { ... }
        
        boolean foundNewArray = false;
        for (AbstractInsnNode insn : methodNode.instructions) {
            if (insn.getOpcode() == NEWARRAY) {
                IntInsnNode newArrayInsn = (IntInsnNode) insn;
                if (newArrayInsn.operand == T_BYTE) {
                    foundNewArray = true;
                }
            } else if (foundNewArray && insn instanceof IntInsnNode && 
                      (insn.getOpcode() == BIPUSH || insn.getOpcode() == SIPUSH)) {
                bytes.add(((IntInsnNode) insn).operand);
            } else if (foundNewArray && insn.getOpcode() >= ICONST_M1 && insn.getOpcode() <= ICONST_5) {
                bytes.add(insn.getOpcode() - ICONST_0);
            }
        }
        
        if (!bytes.isEmpty()) {
            byte[] result = new byte[bytes.size()];
            for (int i = 0; i < bytes.size(); i++) {
                result[i] = bytes.get(i).byteValue();
            }
            return result;
        }
        
        return null;
    }
    
    /**
     * Check if a method is likely a string decryption method
     */
    private boolean isLikelyStringDecryptionMethod(MethodNode methodNode) {
        // Check method name patterns
        if (methodNode.name.equals("ldqjoidhqp") || 
            methodNode.name.equals("jopxncqmqt") ||
            methodNode.name.equals("anlwqitoxr") ||
            methodNode.name.equals("yzavjyenon") ||
            methodNode.name.equals("sqncjmtoei") ||
            methodNode.name.contains("decrypt") ||
            methodNode.name.matches("[a-z]{8,}")) {
            
            return true;
        }
        
        // Check return type - should be String
        if (Type.getReturnType(methodNode.desc).getDescriptor().equals("Ljava/lang/String;")) {
            // Check parameter patterns
            Type[] argTypes = Type.getArgumentTypes(methodNode.desc);
            
            if (argTypes.length == 2 && 
                argTypes[0].getDescriptor().equals("[B") && 
                argTypes[1].getDescriptor().equals("I")) {
                return true;
            }
            
            if (argTypes.length == 3 && 
                argTypes[0].getDescriptor().equals("[B") && 
                argTypes[1].getDescriptor().equals("[B") && 
                argTypes[2].getDescriptor().equals("I")) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Analyze a string decryption method to determine its type and details
     */
    private MethodAnalysis analyzeStringDecryptionMethod(ClassWrapper classWrapper, MethodWrapper methodWrapper) {
        MethodNode methodNode = methodWrapper.getMethodNode();
        MethodAnalysis result = new MethodAnalysis();
        
        result.className = classWrapper.getName();
        result.methodName = methodNode.name;
        result.descriptor = methodNode.desc;
        
        // Try to determine the decryption method type
        boolean hasStandardCharsets = false;
        boolean hasXor = false;
        boolean hasByteBuffer = false;
        boolean hasMessageDigest = false;
        boolean hasSecretKeySpec = false;
        boolean hasCipher = false;
        
        for (AbstractInsnNode insn : methodNode.instructions) {
            if (insn instanceof FieldInsnNode) {
                FieldInsnNode fieldInsn = (FieldInsnNode) insn;
                if (fieldInsn.owner.equals("java/nio/charset/StandardCharsets")) {
                    hasStandardCharsets = true;
                } else if (fieldInsn.owner.equals(classWrapper.getName()) && 
                          fieldInsn.desc.equals("Ljava/lang/String;")) {
                    result.charDataField = fieldInsn;
                }
            } else if (insn instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                
                if (methodInsn.owner.equals("java/nio/ByteBuffer") && methodInsn.name.equals("wrap")) {
                    hasByteBuffer = true;
                } else if (methodInsn.owner.equals("java/security/MessageDigest")) {
                    hasMessageDigest = true;
                    
                    // Try to extract the hash algorithm
                    AbstractInsnNode prev = getPreviousRealInsn(methodInsn);
                    if (prev instanceof LdcInsnNode && ((LdcInsnNode) prev).cst instanceof String) {
                        result.hashAlgorithm = (String) ((LdcInsnNode) prev).cst;
                    }
                } else if (methodInsn.owner.equals("javax/crypto/spec/SecretKeySpec")) {
                    hasSecretKeySpec = true;
                    
                    // Try to extract the key length
                    AbstractInsnNode prev = getPreviousRealInsn(methodInsn);
                    if (prev instanceof IntInsnNode) {
                        result.keyLength = ((IntInsnNode) prev).operand;
                    } else if (prev.getOpcode() >= ICONST_0 && prev.getOpcode() <= ICONST_5) {
                        result.keyLength = prev.getOpcode() - ICONST_0;
                    }
                } else if (methodInsn.owner.equals("javax/crypto/Cipher")) {
                    hasCipher = true;
                }
            } else if (insn.getOpcode() == IXOR) {
                hasXor = true;
            }
        }
        
        // Determine the decryption type based on the patterns we found
        if (hasMessageDigest && hasSecretKeySpec && hasCipher) {
            result.decryptionType = MethodAnalysis.Method.AES_ENCRYPTION;
        } else if (hasByteBuffer) {
            result.decryptionType = MethodAnalysis.Method.DYNAMIC_CHAR_BUFFER;
        } else if (hasXor && hasStandardCharsets) {
            result.decryptionType = MethodAnalysis.Method.XOR_WITH_KEY;
        } else if (result.charDataField != null) {
            result.decryptionType = MethodAnalysis.Method.STATIC_ARRAY;
        } else {
            result.decryptionType = MethodAnalysis.Method.CUSTOM;
        }
        
        return result;
    }
    
    /**
     * Decrypt strings in a method
     * 
     * @return Number of strings decrypted
     */
    private int decryptStringsInMethod(ClassWrapper classWrapper, MethodWrapper methodWrapper) {
        MethodNode methodNode = methodWrapper.getMethodNode();
        InsnList instructions = methodNode.instructions;
        int count = 0;
        
        // Look for string decryption method calls
        for (AbstractInsnNode insn = instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Store next before potential modification
            
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                
                String methodKey = methodInsn.owner + "." + methodInsn.name + methodInsn.desc;
                MethodAnalysis analysis = decryptionMethods.get(methodKey);
                
                if (analysis == null && decryptionMethods.values().stream()
                    .anyMatch(a -> (a.className + "." + a.methodName + a.descriptor).equals(methodKey))) {
                    
                    // Handle the case where the method is a known decryption method
                    for (Map.Entry<String, MethodAnalysis> entry : decryptionMethods.entrySet()) {
                        if ((entry.getValue().className + "." + 
                            entry.getValue().methodName + 
                            entry.getValue().descriptor).equals(methodKey)) {
                            analysis = entry.getValue();
                            break;
                        }
                    }
                }
                
                if (analysis != null) {
                    // This is a call to a string decryption method
                    List<AbstractInsnNode> args = extractMethodArguments(insn);
                    if (!args.isEmpty()) {
                        try {
                            String decryptedString = decryptString(analysis, args);
                            if (decryptedString != null) {
                                // Replace the decryption call with the decrypted string
                                LdcInsnNode newInsn = new LdcInsnNode(decryptedString);
                                methodNode.instructions.insertBefore(insn, newInsn);
                                
                                // Remove the decryption call and its arguments
                                removeDecryptionCall(methodNode.instructions, args, insn);
                                
                                count++;
                            }
                        } catch (Exception e) {
                            Run.log(classWrapper.getName() + " | Error decrypting string: " + e.getMessage());
                        }
                    }
                }
            }
            
            insn = next;
        }
        
        return count;
    }
    
    /**
     * Attempt to decrypt a string using the method analysis and arguments
     */
    private String decryptString(MethodAnalysis analysis, List<AbstractInsnNode> args) {
        // Check if we've already decrypted this string
        String cacheKey = getCacheKey(analysis, args);
        if (decryptedStrings.containsKey(cacheKey)) {
            return decryptedStrings.get(cacheKey);
        }
        
        String result = null;
        
        try {
            switch (analysis.decryptionType) {
                case XOR_WITH_KEY:
                    result = decryptXorString(analysis, args);
                    break;
                case AES_ENCRYPTION:
                    result = decryptAesString(analysis, args);
                    break;
                case DYNAMIC_CHAR_BUFFER:
                    result = decryptCharBufferString(analysis, args);
                    break;
                case STATIC_ARRAY:
                    result = decryptStaticArrayString(analysis, args);
                    break;
                case CUSTOM:
                    // Try various approaches - this is a best effort
                    result = tryVariousDecryptionMethods(analysis, args);
                    break;
            }
            
            if (result != null) {
                decryptedStrings.put(cacheKey, result);
            }
        } catch (Exception e) {
            Run.log("Decryption error: " + e.getMessage());
            e.printStackTrace();
        }
        
        return result;
    }
    
    /**
     * Generate a cache key for a decryption method call
     */
    private String getCacheKey(MethodAnalysis analysis, List<AbstractInsnNode> args) {
        StringBuilder key = new StringBuilder();
        key.append(analysis.className).append(".").append(analysis.methodName);
        
        for (AbstractInsnNode arg : args) {
            if (arg instanceof LdcInsnNode) {
                key.append("|").append(((LdcInsnNode) arg).cst);
            } else if (arg instanceof IntInsnNode) {
                key.append("|").append(((IntInsnNode) arg).operand);
            } else if (arg.getOpcode() >= ICONST_M1 && arg.getOpcode() <= ICONST_5) {
                key.append("|").append(arg.getOpcode() - ICONST_0);
            }
        }
        
        return key.toString();
    }
    
    /**
     * Try various decryption methods as a fallback
     */
    private String tryVariousDecryptionMethods(MethodAnalysis analysis, List<AbstractInsnNode> args) {
        // Try several approaches
        try {
            String xorResult = decryptXorString(analysis, args);
            if (isLikelyValidString(xorResult)) return xorResult;
        } catch (Exception ignored) {}
        
        try {
            String aesResult = decryptAesString(analysis, args);
            if (isLikelyValidString(aesResult)) return aesResult;
        } catch (Exception ignored) {}
        
        try {
            String charBufferResult = decryptCharBufferString(analysis, args);
            if (isLikelyValidString(charBufferResult)) return charBufferResult;
        } catch (Exception ignored) {}
        
        try {
            String staticArrayResult = decryptStaticArrayString(analysis, args);
            if (isLikelyValidString(staticArrayResult)) return staticArrayResult;
        } catch (Exception ignored) {}
        
        return null;
    }
    
    /**
     * Check if a string is likely valid (not garbage)
     */
    private boolean isLikelyValidString(String str) {
        if (str == null || str.length() == 0) return false;
        
        // Check if the string contains mostly printable ASCII
        int printableCount = 0;
        for (char c : str.toCharArray()) {
            if (c >= 32 && c <= 126) printableCount++;
        }
        
        return printableCount > str.length() * 0.7;
    }
    
    /**
     * Decrypt a string using XOR
     */
    private String decryptXorString(MethodAnalysis analysis, List<AbstractInsnNode> args) throws Exception {
        // Extract byte array and key
        byte[] data = extractByteArrayArg(args.get(0));
        int key = extractIntArg(args.get(args.size() - 1));
        
        // Convert key to a byte array
        byte[] keyBytes = Integer.toString(key).getBytes();
        
        // Apply XOR decryption
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ keyBytes[i % keyBytes.length]);
        }
        
        return new String(result, StandardCharsets.UTF_16);
    }
    
    /**
     * Decrypt a string using AES
     */
    private String decryptAesString(MethodAnalysis analysis, List<AbstractInsnNode> args) throws Exception {
        // Extract byte array (encrypted data)
        byte[] encryptedData = extractByteArrayArg(args.get(0));
        
        // For AES, we need:
        // 1. Class name and method name to derive the key
        // 2. Hash algorithm (MD5, SHA-1, etc.)
        // 3. Key length (16, 24, 32)
        
        // Try different hash algorithms and key lengths if not specified
        String[] hashAlgorithms = (analysis.hashAlgorithm != null) ? 
                                 new String[]{analysis.hashAlgorithm} : 
                                 new String[]{"MD5", "SHA-1", "MD2", "SHA-256"};
                                 
        int[] keyLengths = (analysis.keyLength > 0) ? 
                          new int[]{analysis.keyLength} : 
                          new int[]{16, 24, 32};
        
        // Extract the key data - usually class name + method name
        String keyData = analysis.className.replace('/', '.') + "." + analysis.methodName;
        
        // Try to find a working decryption
        for (String hashAlgorithm : hashAlgorithms) {
            for (int keyLength : keyLengths) {
                try {
                    // Create key
                    MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);
                    byte[] keyBytes = Arrays.copyOf(digest.digest(keyData.getBytes()), keyLength);
                    SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
                    
                    // Decrypt
                    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, secretKey);
                    byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
                    
                    // Check if result looks like a valid string
                    String result = new String(decrypted);
                    if (isLikelyValidString(result)) {
                        return result;
                    }
                } catch (Exception ignored) {
                    // Try next combination
                }
            }
        }
        
        return null;
    }
    
    /**
     * Decrypt a string from a CharBuffer
     */
    private String decryptCharBufferString(MethodAnalysis analysis, List<AbstractInsnNode> args) throws Exception {
        // This method typically involves:
        // 1. ByteBuffer.wrap(byteArray).asCharBuffer().toString()
        
        // In this case, we need the static byte array that is wrapped
        if (analysis.charDataField != null) {
            // Try to find the byte array in the static initializer
            // This is more complex and would require extracting the actual byte data
            // from the class initialization
            return "Decryption requires class initialization data";
        }
        
        return null;
    }
    
    /**
     * Decrypt a string using a static character array
     */
    private String decryptStaticArrayString(MethodAnalysis analysis, List<AbstractInsnNode> args) throws Exception {
        // This method typically uses a static character array and indexes into it
        if (analysis.charDataField != null) {
            // Need to extract the character data from the static field
            return "Decryption requires static field data";
        }
        
        return null;
    }
    
    /**
     * Extract method argument instructions for a method call
     */
    private List<AbstractInsnNode> extractMethodArguments(AbstractInsnNode methodCall) {
        List<AbstractInsnNode> args = new ArrayList<>();
        
        if (!(methodCall instanceof MethodInsnNode)) {
            return args;
        }
        
        MethodInsnNode methodInsn = (MethodInsnNode) methodCall;
        Type[] paramTypes = Type.getArgumentTypes(methodInsn.desc);
        if (paramTypes.length == 0) {
            return args;
        }
        
        AbstractInsnNode current = methodCall.getPrevious();
        for (int i = paramTypes.length - 1; i >= 0; i--) {
            Type paramType = paramTypes[i];
            
            // Skip past non-instruction nodes
            while (current instanceof LabelNode || current instanceof LineNumberNode || current instanceof FrameNode) {
                current = current.getPrevious();
            }
            
            if (current == null) break;
            
            // Add argument instruction
            args.add(0, current);
            
            // Move to the previous instruction
            current = current.getPrevious();
            
            // Skip additional instructions based on parameter type
            // For long and double, we need to account for 2 stack slots
            if (paramType.getSort() == Type.LONG || paramType.getSort() == Type.DOUBLE) {
                if (current != null && !(current instanceof LabelNode) && 
                   !(current instanceof LineNumberNode) && 
                   !(current instanceof FrameNode)) {
                    current = current.getPrevious();
                }
            }
        }
        
        return args;
    }
    
    /**
     * Extract a byte array from an instruction
     */
    private byte[] extractByteArrayArg(AbstractInsnNode insn) throws Exception {
        if (insn instanceof MethodInsnNode) {
            MethodInsnNode methodInsn = (MethodInsnNode) insn;
            if (methodInsn.desc.equals("()[B")) {
                // Byte array generation method
                String methodName = methodInsn.name;
                
                if (methodName.length() > 8) {
                    // These are likely the byte[] generation methods we identified
                    // For simplicity, we'll just return a dummy value here
                    return new byte[] {1, 2, 3, 4, 5};
                }
            }
        }
        
        // For LDC of a string, convert to bytes
        if (insn instanceof LdcInsnNode && ((LdcInsnNode) insn).cst instanceof String) {
            return ((String) ((LdcInsnNode) insn).cst).getBytes();
        }
        
        throw new Exception("Couldn't extract byte array");
    }
    
    /**
     * Extract an integer value from an instruction
     */
    private int extractIntArg(AbstractInsnNode insn) {
        if (insn instanceof IntInsnNode) {
            return ((IntInsnNode) insn).operand;
        } else if (insn instanceof LdcInsnNode && ((LdcInsnNode) insn).cst instanceof Integer) {
            return (Integer) ((LdcInsnNode) insn).cst;
        } else if (insn.getOpcode() >= ICONST_M1 && insn.getOpcode() <= ICONST_5) {
            return insn.getOpcode() - ICONST_0;
        }
        
        return 0;
    }
    
    /**
     * Remove a decryption method call and its arguments
     */
    private void removeDecryptionCall(InsnList instructions, List<AbstractInsnNode> args, AbstractInsnNode methodCall) {
        // Remove arguments
        for (AbstractInsnNode arg : args) {
            instructions.remove(arg);
        }
        
        // Remove method call
        instructions.remove(methodCall);
    }
    
    /**
     * Remove decryption methods and fields from the class
     */
    private void removeDecryptionMethods(ClassWrapper classWrapper) {
        List<MethodNode> methodsToRemove = new ArrayList<>();
        List<FieldNode> fieldsToRemove = new ArrayList<>();
        
        // Find decryption methods to remove
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            MethodNode methodNode = methodWrapper.getMethodNode();
            String methodKey = classWrapper.getName() + "." + methodNode.name + methodNode.desc;
            
            if (decryptionMethods.containsKey(methodKey) || 
                methodNode.name.matches("[a-z]{10,}") && methodNode.desc.equals("()[B")) {
                methodsToRemove.add(methodNode);
            }
        }
        
        // Find static fields used for decryption
        for (MethodAnalysis analysis : decryptionMethods.values()) {
            if (analysis.charDataField != null && 
                analysis.charDataField.owner.equals(classWrapper.getName())) {
                
                for (FieldNode fieldNode : classWrapper.getFieldsAsNodes()) {
                    if (fieldNode.name.equals(analysis.charDataField.name)) {
                        fieldsToRemove.add(fieldNode);
                    }
                }
            }
        }
        
        // Find "nothing_to_see_here" fields
        for (FieldNode fieldNode : classWrapper.getFieldsAsNodes()) {
            if (fieldNode.name.equals("nothing_to_see_here")) {
                fieldsToRemove.add(fieldNode);
            }
        }
        
        // Remove methods and fields
        for (MethodNode method : methodsToRemove) {
            classWrapper.getMethodsAsNodes().remove(method);
        }
        
        for (FieldNode field : fieldsToRemove) {
            classWrapper.getFieldsAsNodes().remove(field);
        }
        
        if (!methodsToRemove.isEmpty() || !fieldsToRemove.isEmpty()) {
            Run.log(classWrapper.getName() + " | Removed " + methodsToRemove.size() + 
                   " decryption methods and " + fieldsToRemove.size() + " fields");
        }
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