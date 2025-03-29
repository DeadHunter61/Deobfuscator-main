package dead.owner.deobf.utils.wrapper;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.util.Arrays;
import java.util.stream.Stream;

/**
 * Wrapper for ASM MethodNode to provide utility methods
 */
public final class MethodWrapper {
    private final MethodNode methodNode;
    private final ClassWrapper owner;

    public MethodWrapper(ClassWrapper owner, MethodNode methodNode) {
        this.owner = owner;
        this.methodNode = methodNode;
    }

    public int getAccess() {
        return methodNode.access;
    }

    public void setAccess(int access) {
        methodNode.access = access;
    }

    public String getSignature() {
        return methodNode.signature;
    }

    public void setSignature(String signature) {
        methodNode.signature = signature;
    }

    public String getDescriptor() {
        return methodNode.desc;
    }

    public String getName() {
        return methodNode.name;
    }

    public InsnList getInstructions() {
        return methodNode.instructions;
    }

    public Stream<AbstractInsnNode> getInstructionStream() {
        return Arrays.stream(methodNode.instructions.toArray());
    }

    public String getReturnType() {
        return Type.getReturnType(methodNode.desc).getDescriptor();
    }

    public Type[] getArgumentTypes() {
        return Type.getArgumentTypes(methodNode.desc);
    }

    public String getArgumentsType() {
        var builder = new StringBuilder();
        var args = Type.getArgumentTypes(methodNode.desc);
        for (Type arg : args)
            builder.append(arg.getDescriptor());
        return builder.toString();
    }

    public boolean isStatic() {
        return (getAccess() & Opcodes.ACC_STATIC) != 0;
    }

    public boolean isInitializer() {
        return this.getName().startsWith("<");
    }

    public boolean isClinit() {
        return getName().equals("<clinit>") && getDescriptor().equals("()V");
    }

    public ClassWrapper getOwner() {
        return owner;
    }

    public MethodNode getMethodNode() {
        return methodNode;
    }

    public String getOwnerName() {
        return getOwner().getName();
    }

    @Override
    public String toString() {
        return this.getOwnerName() + "." + this.getName() + " " + this.getDescriptor();
    }
}