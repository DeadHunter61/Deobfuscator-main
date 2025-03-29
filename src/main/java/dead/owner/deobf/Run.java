package dead.owner.deobf;

import java.io.File;
import java.util.Scanner;

/**
 * Main entry point for the deobfuscator
 */
public class Run {
    public static void log(String message) {
        System.out.println("[SimpleDeobfuscator] " + message);
    }
    
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        
        log("Enter obfuscated .jar name or path: ");
        String filePath = scanner.nextLine().trim();
        
        File file = new File(filePath);
        
        if (file.exists()) {
            log("Loaded file: " + file.getAbsolutePath());
            scanner.close();
            log("Processing deobfuscation...");
            
            DeobfuscationProcessor processor = new DeobfuscationProcessor(file);
            processor.start();
            
            synchronized (processor.flagLock) {
                while (processor.getFlag() == null) {
                    try {
                        processor.flagLock.wait();
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }
        } else {
            log("File not found: " + file.getAbsolutePath());
            scanner.close();
        }
        
        log("Deobfuscation completed");
    }
}