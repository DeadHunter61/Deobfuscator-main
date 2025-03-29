package dead.owner.deobf.transformers.skid;

import dead.owner.deobf.Run;
import dead.owner.deobf.utils.wrapper.ClassWrapper;
import dead.owner.deobf.transformers.Transformer;
import org.objectweb.asm.Opcodes;

import java.util.ArrayList;
import java.util.List;

/**
 * Main coordinator for SkidFuscator deobfuscation
 * Applies all SkidFuscator-specific transformers in the correct order
 */
public class SkidFuscatorDeobfuscator implements Transformer, Opcodes {
    private final List<Transformer> transformers;
    
    public SkidFuscatorDeobfuscator() {
        transformers = new ArrayList<>();
        
        // Build the chain of transformers in the correct order
        // First pass - remove basic obfuscations and normalize the code
        transformers.add(new SkidFlowCleaner());
        transformers.add(new SkidStringDecryptor());
        
        // Second pass - restore control flow and structure
        transformers.add(new SkidControlFlowRestorer());
        transformers.add(new SkidNumberUnmasker());
        
        // Third pass - handle more complex obfuscations
        transformers.add(new SkidIndyRemapper());
    }
    
    @Override
    public void transform(ClassWrapper classWrapper) {
        boolean isSkidFuscator = detectSkidFuscator(classWrapper);
        
        if (!isSkidFuscator) {
            return; // Not obfuscated with SkidFuscator
        }
        
        Run.log(classWrapper.getName() + " | Detected SkidFuscator obfuscation");
        
        // Apply each transformer in sequence
        for (Transformer transformer : transformers) {
            transformer.transform(classWrapper);
        }
        
        Run.log(classWrapper.getName() + " | Completed SkidFuscator deobfuscation");
    }
    
    /**
     * Detect if the class was obfuscated with SkidFuscator
     */
    private boolean detectSkidFuscator(ClassWrapper classWrapper) {
        // Check for SkidFuscator markers
        
        // 1. Check for the Driver class
        if (classWrapper.getName().equals("skid/Driver")) {
            return true;
        }
        
        // 2. Check for specific methods
        for (String methodName : new String[]{"get", "hash", "checkType"}) {
            if (classWrapper.findMethod(methodName, "(Ljava/lang/String;)I") != null ||
                classWrapper.findMethod(methodName, "(Ljava/lang/String;)Ljava/lang/String;") != null) {
                return true;
            }
        }
        
        // 3. Look for invokedynamic instructions with specific patterns
        for (org.objectweb.asm.tree.MethodNode methodNode : classWrapper.getMethodsAsNodes()) {
            for (org.objectweb.asm.tree.AbstractInsnNode insn : methodNode.instructions) {
                if (insn instanceof org.objectweb.asm.tree.InvokeDynamicInsnNode) {
                    org.objectweb.asm.tree.InvokeDynamicInsnNode indyInsn = 
                        (org.objectweb.asm.tree.InvokeDynamicInsnNode) insn;
                    if (indyInsn.name.equals("v") || indyInsn.name.contains("_")) {
                        return true;
                    }
                }
            }
        }
        
        // 4. Look for common exception trap patterns
        if (hasExceptionTraps(classWrapper)) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if the class has SkidFuscator's exception trap patterns
     */
    private boolean hasExceptionTraps(ClassWrapper classWrapper) {
        for (org.objectweb.asm.tree.MethodNode methodNode : classWrapper.getMethodsAsNodes()) {
            if (methodNode.tryCatchBlocks == null || methodNode.tryCatchBlocks.isEmpty()) {
                continue;
            }
            
            for (org.objectweb.asm.tree.TryCatchBlockNode tryCatch : methodNode.tryCatchBlocks) {
                // Look for very specific try blocks with custom exception types
                boolean suspicious = false;
                
                // Count instructions in the try block
                int count = countInstructions(methodNode, tryCatch.start, tryCatch.end);
                if (count <= 5) {
                    suspicious = true; // Small try blocks are suspicious
                }
                
                // Check for throw instructions in the try block
                if (hasThrowInstruction(methodNode, tryCatch.start, tryCatch.end)) {
                    suspicious = true;
                }
                
                if (suspicious) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Count real instructions between two labels
     */
    private int countInstructions(org.objectweb.asm.tree.MethodNode methodNode, 
                                org.objectweb.asm.tree.LabelNode start, 
                                org.objectweb.asm.tree.LabelNode end) {
        int count = 0;
        boolean counting = false;
        
        for (org.objectweb.asm.tree.AbstractInsnNode insn : methodNode.instructions) {
            if (insn == start) {
                counting = true;
                continue;
            }
            
            if (insn == end) {
                break;
            }
            
            if (counting && !(insn instanceof org.objectweb.asm.tree.LabelNode) && 
                           !(insn instanceof org.objectweb.asm.tree.LineNumberNode) &&
                           !(insn instanceof org.objectweb.asm.tree.FrameNode)) {
                count++;
            }
        }
        
        return count;
    }
    
    /**
     * Check if there's a throw instruction in a block
     */
    private boolean hasThrowInstruction(org.objectweb.asm.tree.MethodNode methodNode, 
                                      org.objectweb.asm.tree.LabelNode start, 
                                      org.objectweb.asm.tree.LabelNode end) {
        boolean checking = false;
        
        for (org.objectweb.asm.tree.AbstractInsnNode insn : methodNode.instructions) {
            if (insn == start) {
                checking = true;
                continue;
            }
            
            if (insn == end) {
                break;
            }
            
            if (checking && insn.getOpcode() == ATHROW) {
                return true;
            }
        }
        
        return false;
    }
}