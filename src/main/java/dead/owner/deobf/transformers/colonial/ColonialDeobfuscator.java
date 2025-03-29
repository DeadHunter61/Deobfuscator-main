package dead.owner.deobf.transformers.colonial;

import dead.owner.deobf.Run;
import dead.owner.deobf.utils.wrapper.ClassWrapper;
import dead.owner.deobf.transformers.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.util.ArrayList;
import java.util.List;

/**
 * Main coordinator for Colonial Obfuscator deobfuscation
 * Applies all Colonial-specific transformers in the correct order
 */
public class ColonialDeobfuscator implements Transformer, Opcodes {
    private final List<Transformer> transformers;
    
    public ColonialDeobfuscator() {
        transformers = new ArrayList<>();
        
        // Build the chain of transformers in the correct order
        // First pass - clean up flow obfuscations and normalize the code
        transformers.add(new ColonialFlowCleaner());
        transformers.add(new ColonialExceptionRestorer());
        
        // Second pass - handle specific obfuscation techniques
        transformers.add(new ColonialStringDecryptor());
        transformers.add(new ColonialInvokeDynamicResolver());
        
        // Third pass - clean up the class structure
        transformers.add(new ColonialDummyClassRemover());
    }
    
    @Override
    public void transform(ClassWrapper classWrapper) {
        boolean isColonial = detectColonialObfuscator(classWrapper);
        
        if (!isColonial) {
            return; // Not obfuscated with Colonial Obfuscator
        }
        
        Run.log(classWrapper.getName() + " | Detected Colonial obfuscation");
        
        // Apply each transformer in sequence
        for (Transformer transformer : transformers) {
            transformer.transform(classWrapper);
        }
        
        Run.log(classWrapper.getName() + " | Completed Colonial deobfuscation");
    }
    
    /**
     * Detect if the class was obfuscated with Colonial Obfuscator
     */
    private boolean detectColonialObfuscator(ClassWrapper classWrapper) {
        // Check for Colonial markers
        
        // 1. Check for common naming patterns
        if (classWrapper.getName().contains("colonial") || 
            classWrapper.getName().matches(".*[a-zA-Z][0-9a-zA-Z]{10,}")) {
            return true;
        }
        
        // 2. Check for obfuscated field/method name patterns
        int obfuscatedCounter = 0;
        for (FieldNode field : classWrapper.getFieldsAsNodes()) {
            if (field.name.matches("[a-zA-Z][a-zA-Z0-9]{6,12}")) {
                obfuscatedCounter++;
            }
        }
        
        for (MethodNode method : classWrapper.getMethodsAsNodes()) {
            if (!method.name.equals("<init>") && !method.name.equals("<clinit>") &&
                method.name.matches("[a-zA-Z][a-zA-Z0-9]{6,12}")) {
                obfuscatedCounter++;
            }
        }
        
        if (obfuscatedCounter > 5) {
            return true;
        }
        
        // 3. Check for specific invokedynamic patterns
        for (MethodNode methodNode : classWrapper.getMethodsAsNodes()) {
            for (AbstractInsnNode insn : methodNode.instructions) {
                if (insn instanceof InvokeDynamicInsnNode) {
                    InvokeDynamicInsnNode indyInsn = (InvokeDynamicInsnNode) insn;
                    if (indyInsn.name.contains("_") || indyInsn.name.matches("[a-zA-Z0-9]{8,}")) {
                        return true;
                    }
                }
            }
        }
        
        // 4. Check for bootstrap methods with specific patterns
        for (MethodNode methodNode : classWrapper.getMethodsAsNodes()) {
            if (methodNode.name.matches("[a-zA-Z0-9]{8,}") && 
                methodNode.desc.contains("Ljava/lang/invoke/MethodHandles$Lookup;") && 
                methodNode.desc.contains("Ljava/lang/invoke/CallSite;")) {
                
                return true;
            }
        }
        
        // 5. Check for encrypted strings (particular pattern)
        for (MethodNode methodNode : classWrapper.getMethodsAsNodes()) {
            int base64Count = 0;
            int xorCount = 0;
            
            for (AbstractInsnNode insn : methodNode.instructions) {
                if (insn instanceof MethodInsnNode) {
                    MethodInsnNode methodInsn = (MethodInsnNode) insn;
                    if (methodInsn.owner.equals("java/util/Base64") && 
                       (methodInsn.name.equals("getDecoder") || methodInsn.name.equals("decode"))) {
                        base64Count++;
                    }
                } else if (insn.getOpcode() == IXOR) {
                    xorCount++;
                }
            }
            
            if (base64Count > 0 && xorCount > 0) {
                return true;
            }
        }
        
        // 6. Check for specific try-catch patterns
        for (MethodNode methodNode : classWrapper.getMethodsAsNodes()) {
            if (methodNode.tryCatchBlocks != null && !methodNode.tryCatchBlocks.isEmpty()) {
                for (TryCatchBlockNode tryCatch : methodNode.tryCatchBlocks) {
                    // Colonial often uses RuntimeException for control flow
                    if (tryCatch.type != null && 
                       (tryCatch.type.equals("java/lang/RuntimeException") || 
                        tryCatch.type.equals("java/lang/IllegalArgumentException") || 
                        tryCatch.type.equals("java/lang/Exception"))) {
                        
                        // Check if the try block is small
                        int size = countInstructionsInTryBlock(methodNode, tryCatch);
                        if (size < 5) {
                            return true;
                        }
                    }
                }
            }
        }
        
        return false;
    }
    
    /**
     * Count instructions in a try block
     */
    private int countInstructionsInTryBlock(MethodNode methodNode, TryCatchBlockNode tryCatch) {
        int count = 0;
        boolean inTryBlock = false;
        
        for (AbstractInsnNode insn : methodNode.instructions) {
            if (insn == tryCatch.start) {
                inTryBlock = true;
                continue;
            }
            
            if (insn == tryCatch.end) {
                inTryBlock = false;
                break;
            }
            
            if (inTryBlock && !(insn instanceof LabelNode) && 
                             !(insn instanceof LineNumberNode) && 
                             !(insn instanceof FrameNode)) {
                count++;
            }
        }
        
        return count;
    }
}