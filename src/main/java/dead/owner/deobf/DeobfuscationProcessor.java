package dead.owner.deobf;

import dead.owner.deobf.transformers.*;
import dead.owner.deobf.utils.wrapper.ClassWrapper;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * Core processor that handles the deobfuscation process
 */
@RequiredArgsConstructor
public class DeobfuscationProcessor extends Thread {
    private final Map<String, ClassWrapper> CLASSES = new ConcurrentHashMap<>();
    private final Map<String, byte[]> FILES = new ConcurrentHashMap<>();
    private final @NonNull File file;
    
    public final ReentrantLock flagLock = new ReentrantLock();
    private Boolean flag = null;
    
    @Getter
    private final Transformer[] transformers = new Transformer[] {
        new StringDecryptor(),
        new FlowCleaner(),
        new InvokeDynamicRestorer(),
        new MethodHandleCleaner(),
        new ConstructorCleaner(),
        new SignatureCleaner()
    };

    public Boolean getFlag() {
        return flag;
    }

    public void setFlag(Boolean value) {
        synchronized (flagLock) {
            flag = value;
            String strpath = file.getAbsolutePath().replace(".jar", "-deobf.jar");
            if (value)
                saveOutput(new Path(strpath));
            Run.log("File saved to " + strpath);
            CLASSES.clear();
            FILES.clear();
            flagLock.notifyAll();
        }
    }

    @SneakyThrows
    @Override
    public void run() {
        Thread.currentThread().setName("Deobfuscation Processor");
        if (!loadInput(new Path(file.getAbsolutePath()))) {
            setFlag(false);
            return;
        }

        // Process each class for deobfuscation
        for (ClassWrapper classWrapper : CLASSES.values()) {
            Run.log(classWrapper.getName() + " | Processing class...");
            
            // Apply each transformer
            for (Transformer transformer : transformers) {
                Run.log(classWrapper.getName() + " | Applying " + transformer.getClass().getSimpleName() + "...");
                transformer.transform(classWrapper);
            }
            
            Run.log(classWrapper.getName() + " | Deobfuscation complete!");
            Run.log("");
        }
        
        setFlag(true);
    }
    
    private boolean loadInput(@NonNull Path path) {
        try (ZipFile zipFile = new ZipFile(path.path())) {
            zipFile.entries().asIterator().forEachRemaining(
                zipEntry -> {
                    try {
                        var is = zipFile.getInputStream(zipEntry);
                        var name = zipEntry.getName();
                        var buffer = is.readAllBytes();
                        if (isClassFile(name, buffer)) {
                            var wrapper = new ClassWrapper(buffer);
                            CLASSES.put(wrapper.getName(), wrapper);
                        } else FILES.put(name, buffer);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            );
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private void saveOutput(@NonNull Path path) {
        try (ZipOutputStream zipFile = new ZipOutputStream(new FileOutputStream(path.path()))) {
            zipFile.setComment("deobf by ");

            CLASSES.forEach(
                (name, wrapper) -> {
                    try {
                        zipFile.putNextEntry(new ZipEntry(name + ".class"));
                        zipFile.write(wrapper.write());
                        zipFile.closeEntry();
                    } catch (Throwable throwable) {
                        throwable.printStackTrace();
                    }
                }
            );

            FILES.forEach(
                (name, buffer) -> {
                    if (name.endsWith("/"))
                        return;

                    try {
                        zipFile.putNextEntry(new ZipEntry(name));
                        zipFile.write(buffer);
                        zipFile.closeEntry();
                    } catch (Throwable throwable) {
                        throwable.printStackTrace();
                    }
                }
            );
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @SneakyThrows
    boolean isClassFile(@NonNull String entryName, byte @NonNull [] buffer) {
        return (
            (entryName.endsWith(".class") || entryName.endsWith(".class/")) && 
            buffer.length >= 4 && 
            String.format("%02X%02X%02X%02X", buffer[0], buffer[1], buffer[2], buffer[3]).equalsIgnoreCase("cafebabe")
        );
    }

    record Path(@NonNull String path) {
        public File asFile() {
            return new File(path).getAbsoluteFile();
        }
    }
}