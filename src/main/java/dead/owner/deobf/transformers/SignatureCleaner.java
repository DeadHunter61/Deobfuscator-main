package dead.owner.deobf.transformers;

import dead.owner.deobf.Run;
import dead.owner.deobf.utils.wrapper.ClassWrapper;
import dead.owner.deobf.utils.wrapper.FieldWrapper;
import dead.owner.deobf.utils.wrapper.MethodWrapper;
import org.objectweb.asm.tree.AnnotationNode;

import java.util.Iterator;
import java.util.List;

/**
 * Transformer to clean up obfuscated signatures and annotations
 */
public class SignatureCleaner implements Transformer {
    
    @Override
    public void transform(ClassWrapper classWrapper) {
        int count = 0;
        
        // Clean class annotations
        count += cleanAnnotations(classWrapper.getInvisibleAnnotations());
        count += cleanAnnotations(classWrapper.getVisibleAnnotations());
        
        // Clean method signatures and annotations
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            // Check if the signature is very long (likely obfuscated)
            if (methodWrapper.getSignature() != null && methodWrapper.getSignature().length() > 50) {
                methodWrapper.setSignature(null);
                count++;
            }
            
            // Clean method annotations
            if (methodWrapper.getMethodNode().invisibleAnnotations != null) {
                count += cleanAnnotations(methodWrapper.getMethodNode().invisibleAnnotations);
            }
            if (methodWrapper.getMethodNode().visibleAnnotations != null) {
                count += cleanAnnotations(methodWrapper.getMethodNode().visibleAnnotations);
            }
        }
        
        // Clean field signatures and annotations
        for (FieldWrapper fieldWrapper : classWrapper.getFields()) {
            if (fieldWrapper.getFieldNode().signature != null && 
                fieldWrapper.getFieldNode().signature.length() > 50) {
                fieldWrapper.getFieldNode().signature = null;
                count++;
            }
            
            if (fieldWrapper.getFieldNode().invisibleAnnotations != null) {
                count += cleanAnnotations(fieldWrapper.getFieldNode().invisibleAnnotations);
            }
            if (fieldWrapper.getFieldNode().visibleAnnotations != null) {
                count += cleanAnnotations(fieldWrapper.getFieldNode().visibleAnnotations);
            }
        }
        
        if (count > 0) {
            Run.log(classWrapper.getName() + " | Cleaned " + count + " signatures and annotations");
        }
    }
    
    /**
     * Clean obfuscated annotations
     * 
     * @return Number of annotations removed
     */
    private int cleanAnnotations(List<AnnotationNode> annotations) {
        if (annotations == null) {
            return 0;
        }
        
        int count = 0;
        Iterator<AnnotationNode> iterator = annotations.iterator();
        
        while (iterator.hasNext()) {
            AnnotationNode annotation = iterator.next();
            
            // Remove annotations related to the obfuscator
            if (annotation.desc != null && 
                (annotation.desc.contains("javacrawler") || 
                 annotation.desc.contains("Protected by") ||
                 annotation.desc.length() > 100)) {
                iterator.remove();
                count++;
            }
        }
        
        return count;
    }
}