# Minecraft Plugin Deobfuscator

A comprehensive deobfuscator designed to reverse the techniques used by TrickyJavaObfuscator, especially for Minecraft plugins.

## Features

The deobfuscator addresses several obfuscation techniques:

1. **String Decryption** - Identifies and restores encrypted strings
2. **Flow Cleaning** - Removes dead code and useless instructions
3. **InvokeDynamic Restoration** - Converts invokedynamic calls back to normal method invocations
4. **Method Handle Cleaning** - Removes method handle generators
5. **Constructor Cleaning** - Focuses specifically on obfuscated constructors in Minecraft plugins
6. **Signature Cleaning** - Removes obfuscated signatures and annotations

## Project Structure

```
dead.owner.deobf/
├── Run.java                     # Main entry point
├── DeobfuscationProcessor.java  # Core processing logic
├── transformers/                # Specialized transformers
│   ├── Transformer.java         # Base transformer interface
│   ├── StringDecryptor.java     # Decrypts obfuscated strings
│   ├── FlowCleaner.java         # Removes dead code
│   ├── InvokeDynamicRestorer.java  # Restores normal method calls
│   ├── MethodHandleCleaner.java    # Removes method handle generators
│   ├── ConstructorCleaner.java     # Cleans constructor code
│   └── SignatureCleaner.java       # Fixes signatures and annotations
└── utils/                       # Utility classes
    ├── BytecodeUtil.java        # Bytecode analysis helpers
    └── wrapper/                 # ASM wrappers
        ├── ClassWrapper.java    # Wraps ClassNode
        ├── FieldWrapper.java    # Wraps FieldNode
        └── MethodWrapper.java   # Wraps MethodNode
```

## Usage

1. Compile the deobfuscator
2. Run the `Run` class
3. Enter the path to the obfuscated JAR file
4. The deobfuscated JAR will be saved with a "-deobf" suffix

## Dependencies

- ASM (ObjectWeb ASM) for bytecode manipulation
- Lombok for reducing boilerplate code

## How It Works

The deobfuscator operates in several phases:

1. **Loading** - Reads the obfuscated JAR file and loads all classes
2. **Analysis** - Identifies obfuscation patterns in each class
3. **Transformation** - Applies each transformer to clean up the code
4. **Writing** - Saves the deobfuscated classes to a new JAR file

Each transformer specializes in a specific obfuscation technique and can be extended or customized as needed.

## Extending

To add support for additional obfuscation techniques:

1. Create a new class implementing the `Transformer` interface
2. Add your transformation logic in the `transform` method
3. Add your transformer to the array in `DeobfuscationProcessor`

## License

This project is provided for educational purposes only. Use responsibly and only on code you have permission to analyze.
