package dead.owner.deobf.utils.wrapper;

import org.objectweb.asm.tree.FieldNode;

/**
 * Wrapper for ASM FieldNode to provide utility methods
 */
public final class FieldWrapper {
    private final FieldNode fieldNode;
    private final ClassWrapper owner;

    public FieldWrapper(ClassWrapper owner, FieldNode fieldNode) {
        this.owner = owner;
        this.fieldNode = fieldNode;
    }

    public int getAccess() {
        return fieldNode.access;
    }

    public void setAccess(int access) {
        fieldNode.access = access;
    }

    public String getSignature() {
        return fieldNode.signature;
    }

    public void setSignature(String signature) {
        fieldNode.signature = signature;
    }

    public String getDescriptor() {
        return fieldNode.desc;
    }

    public String getName() {
        return fieldNode.name;
    }

    public String getOwnerName() {
        return getOwner().getName();
    }

    public ClassWrapper getOwner() {
        return owner;
    }

    public FieldNode getFieldNode() {
        return fieldNode;
    }

    @Override
    public String toString() {
        return this.getOwnerName() + "." + this.getName() + " " + this.getDescriptor();
    }
}