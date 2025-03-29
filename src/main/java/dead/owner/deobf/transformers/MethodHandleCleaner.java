package dead.owner.deobf.transformers;

import dead.owner.deobf.Run;
import dead.owner.deobf.utils.wrapper.ClassWrapper;
import dead.owner.deobf.utils.wrapper.MethodWrapper;
import org.objectweb.asm.tree.*;

import java.util.Iterator;

/**
 * Transformer to remove method handle generation methods
 */
public class MethodHandleCleaner implements Transformer {
    
    @Override
    public void transform(ClassWrapper classWrapper) {
        int removed = 0;
        
        // Find and remove method handle generation methods
        Iterator<MethodNode> iterator = classWrapper.getMethodsAsNodes().iterator();
        while (iterator.hasNext()) {
            MethodNode method = iterator.next();
            
            // Check if this is a method handle generator
            if (isMethodHandleGenerator(method)) {
                iterator.remove();
                removed++;
            }
        }
        
        if (removed > 0) {
            Run.log(classWrapper.getName() + " | Removed " + removed + " method handle generators");
        }
    }
    
    /**
     * Check if a method is a method handle generator
     */
    private boolean isMethodHandleGenerator(MethodNode method) {
        // Check if it returns a MethodHandle
        if (!method.desc.endsWith(")Ljava/lang/invoke/MethodHandle;")) {
            return false;
        }
        
        // Check for common patterns in method handle generators
        boolean hasLookup = false;
        boolean hasFindStatic = false;
        boolean hasFindVirtual = false;
        
        for (AbstractInsnNode insn : method.instructions) {
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                
                if (methodInsn.owner.equals("java/lang/invoke/MethodHandles") && 
                    methodInsn.name.equals("lookup")) {
                    hasLookup = true;
                } else if (methodInsn.owner.equals("java/lang/invoke/MethodHandles$Lookup")) {
                    if (methodInsn.name.equals("findStatic")) {
                        hasFindStatic = true;
                    } else if (methodInsn.name.equals("findVirtual")) {
                        hasFindVirtual = true;
                    }
                }
            }
        }
        
        return hasLookup && (hasFindStatic || hasFindVirtual);
    }
}