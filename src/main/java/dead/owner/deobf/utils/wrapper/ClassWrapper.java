package dead.owner.deobf.utils.wrapper;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.*;

import java.util.ArrayList;
import java.util.List;

import static org.objectweb.asm.ClassReader.EXPAND_FRAMES;
import static org.objectweb.asm.ClassWriter.COMPUTE_FRAMES;
import static org.objectweb.asm.ClassWriter.COMPUTE_MAXS;

/**
 * Wrapper for ASM ClassNode to provide utility methods
 */
public final class ClassWrapper {
    private final ClassNode classNode;

    public ClassWrapper(byte[] buffer) {
        var classNode = new ClassNode();
        var classReader = new ClassReader(buffer);
        classReader.accept(classNode, EXPAND_FRAMES);
        this.classNode = classNode;
    }

    public ClassWrapper(ClassNode classNode) {
        this.classNode = classNode;
    }

    public String getName() {
        return classNode.name;
    }

    public String getSuperName() {
        return classNode.superName;
    }

    public void setSuperName(String superName) {
        classNode.superName = superName;
    }

    public int getAccess() {
        return classNode.access;
    }

    public void setAccess(int access) {
        classNode.access = access;
    }

    public String getSourceFile() {
        return classNode.sourceFile;
    }

    public void setSourceFile(String sourceFile) {
        classNode.sourceFile = sourceFile;
    }

    public List<AnnotationNode> getInvisibleAnnotations() {
        if (classNode.invisibleAnnotations == null)
            classNode.invisibleAnnotations = new ArrayList<>();
        return classNode.invisibleAnnotations;
    }

    public List<AnnotationNode> getVisibleAnnotations() {
        if (classNode.visibleAnnotations == null)
            classNode.visibleAnnotations = new ArrayList<>();
        return classNode.visibleAnnotations;
    }

    public List<TypeAnnotationNode> getInvisibleTypeAnnotations() {
        if (classNode.invisibleTypeAnnotations == null)
            classNode.invisibleTypeAnnotations = new ArrayList<>();
        return classNode.invisibleTypeAnnotations;
    }

    public List<TypeAnnotationNode> getVisibleTypeAnnotations() {
        if (classNode.visibleTypeAnnotations == null)
            classNode.visibleTypeAnnotations = new ArrayList<>();
        return classNode.visibleTypeAnnotations;
    }

    public List<MethodWrapper> getMethods() {
        var methods = new ArrayList<MethodWrapper>();
        for (var method : classNode.methods)
            methods.add(new MethodWrapper(this, method));
        return methods;
    }

    public List<MethodNode> getMethodsAsNodes() {
        return classNode.methods;
    }

    public MethodWrapper findMethod(String name, String desc) {
        return this.getMethods().stream()
            .filter(method -> method.getName().equals(name) && method.getDescriptor().equals(desc))
            .findFirst()
            .orElse(null);
    }

    public List<FieldWrapper> getFields() {
        var fields = new ArrayList<FieldWrapper>();
        for (var field : classNode.fields)
            fields.add(new FieldWrapper(this, field));
        return fields;
    }

    public List<FieldNode> getFieldsAsNodes() {
        return classNode.fields;
    }

    public FieldWrapper getFieldOrNull(String name, String desc) {
        return getFields().stream()
            .filter(field -> field.getName().equals(name) && field.getDescriptor().equals(desc))
            .findAny()
            .orElse(null);
    }

    public ClassNode getClassNode() {
        return classNode;
    }

    public byte[] write() {
        ClassWriter classWriter = new ClassWriter(COMPUTE_MAXS | COMPUTE_FRAMES);
        classNode.accept(classWriter);
        return classWriter.toByteArray();
    }
}