package dead.owner.deobf.transformers;

import dead.owner.deobf.utils.wrapper.ClassWrapper;

/**
 * Interface for all deobfuscation transformers
 */
public interface Transformer {
    /**
     * Apply the transformation to a given class
     *
     * @param classWrapper The class to transform
     */
    void transform(ClassWrapper classWrapper);
}