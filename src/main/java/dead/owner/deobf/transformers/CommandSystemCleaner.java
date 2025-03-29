package dead.owner.deobf.transformers;

import dead.owner.deobf.Run;
import dead.owner.deobf.utils.wrapper.ClassWrapper;
import dead.owner.deobf.utils.wrapper.MethodWrapper;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.util.*;

/**
 * Transformer to clean up and simplify the command system found in the obfuscated code
 */
public class CommandSystemCleaner implements Transformer, Opcodes {
    
    private static final String[] COMMAND_HANDLER_CLASSES = {
        "yo/zeru/Handler/in/",
        "Handler/in/"
    };
    
    private static final String INITIALIZER_CLASS = "yo/zeru/Handler/Initializator";
    private static final String REGISTER_CLASS = "yo/zeru/Handler/Register";
    
    @Override
    public void transform(ClassWrapper classWrapper) {
        // Check if this is the Initializer class
        if (classWrapper.getName().equals(INITIALIZER_CLASS)) {
            cleanInitializer(classWrapper);
            return;
        }
        
        // Check if this is a command handler class
        for (String prefix : COMMAND_HANDLER_CLASSES) {
            if (classWrapper.getName().startsWith(prefix)) {
                cleanCommandHandler(classWrapper);
                return;
            }
        }
        
        // Check if this is the Register class
        if (classWrapper.getName().equals(REGISTER_CLASS)) {
            cleanRegisterClass(classWrapper);
            return;
        }
    }
    
    /**
     * Clean the Initializer class
     */
    private void cleanInitializer(ClassWrapper classWrapper) {
        // Simplify the event handler method
        MethodWrapper eventHandler = null;
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            MethodNode methodNode = methodWrapper.getMethodNode();
            
            // Look for the event handler method
            if (methodNode.name.matches("abv") && 
                methodNode.desc.endsWith("AsyncPlayerChatEvent;)V") && 
                (methodNode.access & ACC_PRIVATE) != 0) {
                
                eventHandler = methodWrapper;
                break;
            }
        }
        
        // Clean up the event handler if found
        if (eventHandler != null) {
            cleanEventHandler(classWrapper, eventHandler);
            Run.log(classWrapper.getName() + " | Cleaned command handler event");
        }
        
        // Simplify the command registration in the constructor
        MethodWrapper constructor = classWrapper.findMethod("<init>", "()V");
        if (constructor != null) {
            simplifyCommandRegistration(constructor);
            Run.log(classWrapper.getName() + " | Simplified command registration");
        }
    }
    
    /**
     * Clean a command handler class
     */
    private void cleanCommandHandler(ClassWrapper classWrapper) {
        // Rename the class to something more meaningful if we can determine the command name
        String commandName = extractCommandName(classWrapper);
        if (commandName != null) {
            // Just log the command name, actual renaming would happen in a separate transformer
            Run.log(classWrapper.getName() + " | Identified command: " + commandName);
        }
        
        // Clean up the onCommand method
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            if (methodWrapper.getName().equals("onCommand")) {
                cleanOnCommandMethod(methodWrapper);
                Run.log(classWrapper.getName() + " | Cleaned command handler method");
                break;
            }
        }
    }
    
    /**
     * Clean the Register class
     */
    private void cleanRegisterClass(ClassWrapper classWrapper) {
        // Simplify the getName method
        for (MethodWrapper methodWrapper : classWrapper.getMethods()) {
            if (methodWrapper.getName().equals("getName")) {
                simplifyGetNameMethod(methodWrapper);
                Run.log(classWrapper.getName() + " | Simplified getName method");
                break;
            }
        }
    }
    
    /**
     * Clean the event handler method
     */
    private void cleanEventHandler(ClassWrapper classWrapper, MethodWrapper eventHandler) {
        MethodNode methodNode = eventHandler.getMethodNode();
        
        // First, rename the method to a more meaningful name
        methodNode.name = "onAsyncPlayerChat";
        
        // Replace obfuscated control flow with straightforward code
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Store next before potential modification
            
            // Look for complex control flow and simplified it
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                
                // Replace complicated conditions with simpler ones
                if (methodInsn.name.equals("xhrwevfwjdjhyfeh") || 
                    methodInsn.name.equals("nudzrwhrluemgkta") || 
                    methodInsn.name.equals("ttsgbhaeitkbgppm")) {
                    
                    // Find the surrounding control flow and simplify it
                    simplifyControlFlow(methodNode, insn);
                }
            }
            
            insn = next;
        }
        
        // Clean up the event handler's message parsing logic
        AbstractInsnNode getMessageCall = null;
        
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                
                if (methodInsn.name.equals("getMessage") && 
                    methodInsn.desc.equals("()Ljava/lang/String;")) {
                    getMessageCall = insn;
                    break;
                }
            }
        }
        
        if (getMessageCall != null) {
            // Look for string tokenization method calls near the getMessage call
            for (AbstractInsnNode insn = getMessageCall; insn != null; insn = insn.getNext()) {
                if (insn instanceof MethodInsnNode) {
                    MethodInsnNode methodInsn = (MethodInsnNode) insn;
                    
                    if (methodInsn.name.equals("b") && methodInsn.desc.endsWith("([Ljava/lang/String;")) {
                        // This is likely the command tokenization method
                        methodInsn.name = "tokenizeCommand";
                    }
                }
            }
        }
    }
    
    /**
     * Simplify command registration in the constructor
     */
    private void simplifyCommandRegistration(MethodWrapper constructor) {
        MethodNode methodNode = constructor.getMethodNode();
        
        // Look for the commands list initialization
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof FieldInsnNode) {
                FieldInsnNode fieldInsn = (FieldInsnNode) insn;
                
                if (fieldInsn.name.equals("commands") && 
                    fieldInsn.desc.equals("Ljava/util/List;") && 
                    fieldInsn.getOpcode() == GETSTATIC) {
                    
                    // This is the commands list - look for the addAll call
                    AbstractInsnNode current = fieldInsn;
                    while (current != null) {
                        if (current instanceof MethodInsnNode) {
                            MethodInsnNode methodInsn = (MethodInsnNode) current;
                            
                            if (methodInsn.name.equals("addAll") && 
                                methodInsn.owner.equals("java/util/List")) {
                                
                                // This is where commands are added - simplify the code
                                current = simplifyCommandInitialization(methodNode, fieldInsn, methodInsn);
                                break;
                            }
                        }
                        
                        current = current.getNext();
                    }
                    
                    break;
                }
            }
        }
    }
    
    /**
     * Simplify command initialization code
     */
    private AbstractInsnNode simplifyCommandInitialization(MethodNode methodNode, 
                                                         AbstractInsnNode startInsn, 
                                                         AbstractInsnNode endInsn) {
        // Create a map of variable indices to command classes
        Map<Integer, String> varToCommand = new HashMap<>();
        
        // Scan between start and end instructions to find command instantiations
        AbstractInsnNode current = startInsn;
        while (current != endInsn) {
            if (current instanceof TypeInsnNode && current.getOpcode() == NEW) {
                TypeInsnNode typeInsn = (TypeInsnNode) current;
                
                // Look for command class instantiation
                if (typeInsn.desc.endsWith("Command")) {
                    // Find the variable store
                    AbstractInsnNode varStoreInsn = findNextVarStore(current);
                    if (varStoreInsn != null && varStoreInsn instanceof VarInsnNode) {
                        int varIndex = ((VarInsnNode) varStoreInsn).var;
                        varToCommand.put(varIndex, typeInsn.desc);
                    }
                }
            }
            
            current = current.getNext();
        }
        
        // Now clean up the command registration code
        return endInsn;
    }
    
    /**
     * Clean the onCommand method of a command handler
     */
    private void cleanOnCommandMethod(MethodWrapper methodWrapper) {
        MethodNode methodNode = methodWrapper.getMethodNode();
        
        // First, clean up the method descriptor if it has obfuscated parameter types
        if (methodNode.desc.contains("I)")) {
            // Last parameter is likely just an obfuscation int
            Type returnType = Type.getReturnType(methodNode.desc);
            Type[] argTypes = Type.getArgumentTypes(methodNode.desc);
            
            if (argTypes.length > 0 && argTypes[argTypes.length - 1].equals(Type.INT_TYPE)) {
                // Remove the last parameter
                Type[] newArgTypes = new Type[argTypes.length - 1];
                System.arraycopy(argTypes, 0, newArgTypes, 0, argTypes.length - 1);
                
                // Create new descriptor
                methodNode.desc = Type.getMethodDescriptor(returnType, newArgTypes);
            }
        }
        
        // Next, clean up the control flow
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Store next before potential modification
            
            // Look for complex control flow and simplified it
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                
                // Replace complicated conditions with simpler ones
                if (methodInsn.name.equals("xhrwevfwjdjhyfeh") || 
                    methodInsn.name.equals("nudzrwhrluemgkta") || 
                    methodInsn.name.equals("ttsgbhaeitkbgppm")) {
                    
                    // Find the surrounding control flow and simplify it
                    simplifyControlFlow(methodNode, insn);
                }
            }
            
            insn = next;
        }
    }
    
    /**
     * Simplify the getName method in the Register class
     */
    private void simplifyGetNameMethod(MethodWrapper methodWrapper) {
        MethodNode methodNode = methodWrapper.getMethodNode();
        
        // First, clean up the method descriptor if it has obfuscated parameter types
        if (methodNode.desc.contains("(I)")) {
            // Parameter is likely just an obfuscation int
            methodNode.desc = methodNode.desc.replace("(I)", "()");
        }
        
        // Next, clean up the method body
        boolean modified = false;
        
        for (AbstractInsnNode insn = methodNode.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext(); // Store next before potential modification
            
            // Look for the field load followed by a return
            if (insn instanceof FieldInsnNode && insn.getOpcode() == GETFIELD) {
                FieldInsnNode fieldInsn = (FieldInsnNode) insn;
                
                if (fieldInsn.name.equals("name") && fieldInsn.desc.equals("Ljava/lang/String;")) {
                    // Check if the next instruction is a return
                    AbstractInsnNode nextInsn = getNextRealInsn(insn);
                    if (nextInsn != null && nextInsn.getOpcode() == ARETURN) {
                        // This is the simple pattern we want - remove everything else
                        AbstractInsnNode current = methodNode.instructions.getFirst();
                        
                        while (current != null && current != insn) {
                            AbstractInsnNode toRemove = current;
                            current = current.getNext();
                            
                            // Don't remove labels or line numbers
                            if (!(toRemove instanceof LabelNode) && 
                                !(toRemove instanceof LineNumberNode) && 
                                !(toRemove instanceof FrameNode)) {
                                methodNode.instructions.remove(toRemove);
                                modified = true;
                            }
                        }
                        
                        // Skip to the end
                        next = nextInsn.getNext();
                    }
                }
            }
            
            insn = next;
        }
    }
    
    /**
     * Extract the command name from a command handler class
     */
    private String extractCommandName(ClassWrapper classWrapper) {
        // Check for the CommandInfo annotation on the class
        if (classWrapper.getInvisibleAnnotations() != null) {
            for (AnnotationNode annotation : classWrapper.getInvisibleAnnotations()) {
                if (annotation.desc.equals("Lyo/zeru/Handler/CommandInfo;") || 
                    annotation.desc.endsWith("CommandInfo;")) {
                    
                    // Extract the name from the annotation
                    if (annotation.values != null) {
                        for (int i = 0; i < annotation.values.size(); i += 2) {
                            if (annotation.values.get(i).equals("name") && 
                                annotation.values.get(i + 1) instanceof String) {
                                return (String) annotation.values.get(i + 1);
                            }
                        }
                    }
                }
            }
        }
        
        // Try to extract from the class name
        String className = classWrapper.getName();
        int lastSlash = className.lastIndexOf('/');
        if (lastSlash >= 0) {
            className = className.substring(lastSlash + 1);
        }
        
        if (className.endsWith("Command")) {
            return className.substring(0, className.length() - "Command".length()).toLowerCase();
        }
        
        return null;
    }
    
    /**
     * Simplify control flow around a method call
     */
    private void simplifyControlFlow(MethodNode methodNode, AbstractInsnNode methodCallInsn) {
        // Find any switch statement that follows this method call
        AbstractInsnNode switchInsn = findNextSwitch(methodCallInsn);
        if (switchInsn == null) {
            return;
        }
        
        // Check if there's a constant value being pushed before this call
        AbstractInsnNode prev = getPreviousRealInsn(methodCallInsn);
        if (prev == null || !isConstantPush(prev)) {
            return;
        }
        
        // Find and remove the entire control flow sequence
        List<AbstractInsnNode> toRemove = new ArrayList<>();
        toRemove.add(prev);
        toRemove.add(methodCallInsn);
        toRemove.add(switchInsn);
        
        // Replace with a direct jump to the first non-default target
        LabelNode targetLabel = null;
        
        if (switchInsn instanceof TableSwitchInsnNode) {
            TableSwitchInsnNode tableSwitchNode = (TableSwitchInsnNode) switchInsn;
            if (!tableSwitchNode.labels.isEmpty()) {
                targetLabel = tableSwitchNode.labels.get(0);
            } else {
                targetLabel = tableSwitchNode.dflt;
            }
        } else if (switchInsn instanceof LookupSwitchInsnNode) {
            LookupSwitchInsnNode lookupSwitchNode = (LookupSwitchInsnNode) switchInsn;
            if (!lookupSwitchNode.labels.isEmpty()) {
                targetLabel = lookupSwitchNode.labels.get(0);
            } else {
                targetLabel = lookupSwitchNode.dflt;
            }
        }
        
        if (targetLabel != null) {
            // Create a GOTO to the target
            JumpInsnNode gotoInsn = new JumpInsnNode(GOTO, targetLabel);
            methodNode.instructions.insertBefore(prev, gotoInsn);
            
            // Remove the old instructions
            for (AbstractInsnNode insn : toRemove) {
                methodNode.instructions.remove(insn);
            }
        }
    }
    
    /**
     * Find the next switch instruction
     */
    private AbstractInsnNode findNextSwitch(AbstractInsnNode startInsn) {
        AbstractInsnNode current = startInsn.getNext();
        
        while (current != null) {
            if (current instanceof TableSwitchInsnNode || current instanceof LookupSwitchInsnNode) {
                return current;
            }
            
            // Don't go too far
            if (current instanceof JumpInsnNode || 
                (current.getOpcode() >= IRETURN && current.getOpcode() <= RETURN)) {
                break;
            }
            
            current = current.getNext();
        }
        
        return null;
    }
    
    /**
     * Check if an instruction is pushing a constant value
     */
    private boolean isConstantPush(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        
        return (opcode >= ICONST_M1 && opcode <= ICONST_5) ||
               (opcode >= LCONST_0 && opcode <= LCONST_1) ||
               (opcode >= FCONST_0 && opcode <= FCONST_2) ||
               (opcode >= DCONST_0 && opcode <= DCONST_1) ||
               opcode == BIPUSH || 
               opcode == SIPUSH || 
               (insn instanceof LdcInsnNode);
    }
    
    /**
     * Find the next variable store instruction
     */
    private AbstractInsnNode findNextVarStore(AbstractInsnNode startInsn) {
        AbstractInsnNode current = startInsn.getNext();
        
        while (current != null) {
            int opcode = current.getOpcode();
            if (opcode >= ISTORE && opcode <= ASTORE) {
                return current;
            }
            
            current = current.getNext();
        }
        
        return null;
    }
    
    /**
     * Get the next significant instruction
     */
    private AbstractInsnNode getNextRealInsn(AbstractInsnNode insn) {
        AbstractInsnNode current = insn.getNext();
        while (current != null && (current instanceof LabelNode || 
                                  current instanceof LineNumberNode || 
                                  current instanceof FrameNode)) {
            current = current.getNext();
        }
        return current;
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