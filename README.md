# Advanced Minecraft Plugin Deobfuscator

A comprehensive deobfuscator designed specifically for malicious Minecraft plugins obfuscated with TrickyJavaObfuscator and similar tools. This deobfuscator can handle advanced obfuscation techniques including complex control flow obfuscation, string encryption, and invokedynamic transformations.

## Features

The deobfuscator addresses multiple layers of obfuscation:

### First Pass - Complex Obfuscation Techniques
1. **Control Flow Obfuscation** (`XufptsyuqCleaner`) - Removes obfuscated control flow using the xufptsyuqyfygcsb class
2. **Advanced String Decryption** (`EnhancedStringDecryptor`) - Handles multiple encryption methods including AES, XOR, and ByteBuffer transformation
3. **Try-Catch Simplification** (`TryCatchSimplifier`) - Cleans up obfuscated try-catch blocks used to hide control flow

### Second Pass - Specific Code Patterns
4. **Flow Cleaning** (`FlowCleaner`) - Removes dead code and useless instructions
5. **InvokeDynamic Restoration** (`InvokeDynamicRestorer`) - Converts invokedynamic calls back to normal method invocations
6. **Method Handle Cleaning** (`MethodHandleCleaner`) - Removes method handle generators
7. **Useless Code Removal** (`UselessCodeRemover`) - Removes code that serves no purpose but obfuscation

### Third Pass - General Cleanup
8. **Constructor Cleaning** (`ConstructorCleaner`) - Cleans up obfuscated constructors in Minecraft plugins
9. **Static Initializer Cleaning** (`StaticInitializerCleaner`) - Removes ASCII art, ByteBuffer.wrap transformations, and Random initialization
10. **Command System Cleaning** (`CommandSystemCleaner`) - Simplifies obfuscated command handling systems
11. **Signature Cleaning** (`SignatureCleaner`) - Removes obfuscated signatures and annotations

### Final Pass - Readability Improvements
12. **Variable Renaming** (`VariableRenamer`) - Renames obfuscated fields, methods, and local variables to more meaningful names

## Project Structure

```
dead.owner.deobf/
├── Run.java                        # Main entry point
├── DeobfuscationProcessor.java     # Core processing logic
├── transformers/                   # Specialized transformers
│   ├── Transformer.java            # Base transformer interface
│   ├── XufptsyuqCleaner.java       # Cleans control flow obfuscation
│   ├── EnhancedStringDecryptor.java # Advanced string decryption
│   ├── TryCatchSimplifier.java     # Simplifies obfuscated try-catch blocks
│   ├── FlowCleaner.java            # Removes dead code
│   ├── InvokeDynamicRestorer.java  # Restores normal method calls
│   ├── MethodHandleCleaner.java    # Removes method handle generators
│   ├── UselessCodeRemover.java     # Removes purposeless code
│   ├── ConstructorCleaner.java     # Cleans constructor code
│   ├── StaticInitializerCleaner.java # Cleans static initializers
│   ├── CommandSystemCleaner.java   # Simplifies command system
│   ├── SignatureCleaner.java       # Fixes signatures and annotations
│   └── VariableRenamer.java        # Improves naming
└── utils/                          # Utility classes
    ├── BytecodeUtil.java           # Bytecode analysis helpers
    └── wrapper/                    # ASM wrappers
        ├── ClassWrapper.java       # Wraps ClassNode
        ├── FieldWrapper.java       # Wraps FieldNode
        └── MethodWrapper.java      # Wraps MethodNode
```

## Usage

1. Compile the deobfuscator
2. Run the `Run` class
3. Enter the path to the obfuscated JAR file
4. The deobfuscator will process the file and save a deobfuscated version with "-deobf" suffix

## Dependencies

- ASM (ObjectWeb ASM) for bytecode manipulation
- Lombok for reducing boilerplate code

## Handling Specific Obfuscation Techniques

### String Decryption
The deobfuscator can handle several string decryption methods:
- AES encryption with various key derivation methods
- XOR transformations with integer keys
- ByteBuffer/CharBuffer transformations
- Custom static array lookups

### Control Flow Obfuscation
The deobfuscator is specifically designed to handle the complex control flow obfuscation using:
- Obfuscated switch statements
- Try-catch blocks used for flow control
- Fake exception handling
- XOR operations for hash calculation

### Command System Handling
The deobfuscator understands the specific structure of the obfuscated command system found in malicious plugins and can:
- Clean event handlers
- Simplify command registration
- Properly identify command classes

## Security Notice

This deobfuscator was designed to analyze potentially malicious Minecraft plugins. Use it only on code you have permission to analyze, and never run unknown deobfuscated plugins on production servers without thorough review.

## License

This project is provided for educational and security research purposes only. Use responsibly and ethically.
