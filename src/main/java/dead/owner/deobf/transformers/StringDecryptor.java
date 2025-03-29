package dead.owner.deobf.transformers;

import dead.owner.deobf.Run;
import dead.owner.deobf.utils.wrapper.ClassWrapper;
import dead.owner.deobf.utils.wrapper.MethodWrapper;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Transformer to decrypt strings that were encrypted by the obfuscator
 */
public class StringDecryptor implements Transformer, Opcodes {
    private static final Map<String, String> decryptionCache = new HashMap<>();
    private static final String[] HASHERS = {"MD2", "MD5", "SHA-1", "SHA-256"};
    private static final int[] KEY_LENGTHS = {16, 24, 32};
    
    @Override
    public void transform(ClassWrapper classWrapper) {
        // First, identify string decryption methods
        MethodNode decryptionMethod = findDecryptionMethod(classWrapper);
        if (decryptionMethod == null) {
            return;
        }
        
        // Now find and replace all encrypted strings
        int stringCount = 0;
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            if (methodWrapper.getMethodNode() == decryptionMethod) {
                continue; // Skip the decryption method itself
            }
            
            stringCount += decryptStringsInMethod(classWrapper, methodWrapper);
        }
        
        // Remove the decryption method as it's no longer needed
        classWrapper.getMethodsAsNodes().remove(decryptionMethod);
        
        if (stringCount > 0) {
            Run.log(classWrapper.getName() + " | Decrypted " + stringCount + " strings");
        }
    }
    
    /**
     * Find the string decryption method in a class
     */
    private MethodNode findDecryptionMethod(ClassWrapper classWrapper) {
        for (MethodNode method : classWrapper.getMethodsAsNodes()) {
            // The decryption method takes a byte array and StackTraceElement and returns a byte array
            if (method.desc.equals("([BLjava/lang/StackTraceElement;)[B")) {
                // Check for common patterns in the decryption method
                boolean hasMessageDigest = false;
                boolean hasSecretKeySpec = false;
                boolean hasCipher = false;
                
                for (AbstractInsnNode insn : method.instructions) {
                    if (insn instanceof MethodInsnNode) {
                        MethodInsnNode methodInsn = (MethodInsnNode) insn;
                        if (methodInsn.owner.equals("java/security/MessageDigest")) {
                            hasMessageDigest = true;
                        } else if (methodInsn.owner.equals("javax/crypto/spec/SecretKeySpec")) {
                            hasSecretKeySpec = true;
                        } else if (methodInsn.owner.equals("javax/crypto/Cipher")) {
                            hasCipher = true;
                        }
                    }
                }
                
                if (hasMessageDigest && hasSecretKeySpec && hasCipher) {
                    return method;
                }
            }
        }
        
        return null;
    }
    
    /**
     * Decrypt all strings in a method
     * 
     * @return The number of strings decrypted
     */
    private int decryptStringsInMethod(ClassWrapper classWrapper, MethodWrapper methodWrapper) {
        InsnList instructions = methodWrapper.getInstructions();
        int count = 0;
        
        // Look for the Throwable/StackTraceElement pattern
        for (AbstractInsnNode insn = instructions.getFirst(); insn != null;) {
            AbstractInsnNode next = insn.getNext(); // Store next before potential modification
            
            if (isStringDecryptionStart(insn)) {
                // Found the start of a string decryption sequence
                AbstractInsnNode encryptedNode = findEncryptedStringNode(insn);
                if (encryptedNode instanceof LdcInsnNode && ((LdcInsnNode) encryptedNode).cst instanceof String) {
                    String encryptedString = (String) ((LdcInsnNode) encryptedNode).cst;
                    String decryptedString = decryptString(encryptedString, classWrapper.getName(), methodWrapper.getName());
                    
                    if (decryptedString != null) {
                        // Replace the encrypted string with the decrypted string
                        AbstractInsnNode endNode = findEndOfDecryptionSequence(insn);
                        if (endNode != null) {
                            // Insert the decrypted string
                            LdcInsnNode newNode = new LdcInsnNode(decryptedString);
                            instructions.insertBefore(insn, newNode);
                            
                            // Remove the entire decryption sequence
                            AbstractInsnNode current = insn;
                            while (current != endNode.getNext()) {
                                AbstractInsnNode toRemove = current;
                                current = current.getNext();
                                instructions.remove(toRemove);
                            }
                            
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
     * Check if this instruction is the start of a string decryption sequence
     */
    private boolean isStringDecryptionStart(AbstractInsnNode insn) {
        // The pattern starts with NEW Throwable
        if (!(insn instanceof TypeInsnNode) || !((TypeInsnNode) insn).desc.equals("java/lang/Throwable")) {
            return false;
        }
        
        // Check for DUP
        AbstractInsnNode next = insn.getNext();
        if (next == null || next.getOpcode() != DUP) {
            return false;
        }
        
        // Check for INVOKESPECIAL Throwable.<init>
        next = next.getNext();
        if (next == null || !(next instanceof MethodInsnNode) || 
            !((MethodInsnNode) next).owner.equals("java/lang/Throwable") || 
            !((MethodInsnNode) next).name.equals("<init>")) {
            return false;
        }
        
        // Check for INVOKEVIRTUAL getStackTrace
        next = next.getNext();
        if (next == null || !(next instanceof MethodInsnNode) || 
            !((MethodInsnNode) next).owner.equals("java/lang/Throwable") || 
            !((MethodInsnNode) next).name.equals("getStackTrace")) {
            return false;
        }
        
        return true;
    }
    
    /**
     * Find the LDC node containing the encrypted string
     */
    private AbstractInsnNode findEncryptedStringNode(AbstractInsnNode start) {
        AbstractInsnNode current = start;
        while (current != null) {
            if (current instanceof LdcInsnNode && ((LdcInsnNode) current).cst instanceof String) {
                return current;
            }
            current = current.getNext();
            
            // Don't go too far
            if (current instanceof MethodInsnNode && 
                ((MethodInsnNode) current).owner.equals("java/lang/String") && 
                ((MethodInsnNode) current).name.equals("<init>")) {
                break;
            }
        }
        return null;
    }
    
    /**
     * Find the end of the string decryption sequence
     */
    private AbstractInsnNode findEndOfDecryptionSequence(AbstractInsnNode start) {
        AbstractInsnNode current = start;
        while (current != null) {
            if (current instanceof MethodInsnNode && 
                ((MethodInsnNode) current).owner.equals("java/lang/String") && 
                ((MethodInsnNode) current).name.equals("<init>") && 
                ((MethodInsnNode) current).desc.equals("([B)V")) {
                return current;
            }
            current = current.getNext();
        }
        return null;
    }
    
    /**
     * Decrypt an encrypted string
     */
    private String decryptString(String encryptedString, String className, String methodName) {
        // Use cache if available
        String cacheKey = encryptedString + "|" + className + "|" + methodName;
        if (decryptionCache.containsKey(cacheKey)) {
            return decryptionCache.get(cacheKey);
        }
        
        // Try different hashing algorithms and key lengths until one works
        for (String hasher : HASHERS) {
            for (int keyLength : KEY_LENGTHS) {
                try {
                    String decrypted = attemptDecryption(encryptedString, className, methodName, hasher, keyLength);
                    // Cache the result
                    decryptionCache.put(cacheKey, decrypted);
                    return decrypted;
                } catch (Exception ignored) {
                    // Try the next combination
                }
            }
        }
        
        // If all decryption attempts fail, return null
        return null;
    }
    
    /**
     * Attempt to decrypt a string with specific parameters
     */
    private String attemptDecryption(String encryptedString, String className, String methodName, 
                                    String hasher, int keyLength) throws Exception {
        className = className.replace('/', '.');
        
        MessageDigest messageDigest = MessageDigest.getInstance(hasher);
        SecretKeySpec secretKey = new SecretKeySpec(
            Arrays.copyOf(messageDigest.digest((className + methodName).getBytes()), keyLength), 
            "AES"
        );
        
        Cipher decoder = Cipher.getInstance("AES/ECB/PKCS5Padding");
        decoder.init(Cipher.DECRYPT_MODE, secretKey);
        
        return new String(decoder.doFinal(Base64.getDecoder().decode(encryptedString.getBytes())));
    }
}