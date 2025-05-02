package server;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import javax.crypto.SecretKey;

public class Test {

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java server.Test <action> <file-path>");
            System.out.println("Actions:");
            System.out.println("  encrypt-file    Encrypt the specified file");
            System.out.println("  decrypt-file    Decrypt the specified file");
            System.exit(1);
        }

        String action = args[0];
        File inputFile = new File(args[1]);

        if (!inputFile.exists()) {
            System.err.println("File not found: " + args[1]);
            System.exit(1);
        }

        try {
            // Load the config
            DRMSystem drm = new DRMSystem();
            DRMSystem.processArgs(new String[]{}); // load config (default path or specified)

            if ("encrypt-file".equals(action)) {
                // Encrypt the file
                drm.protectContent(inputFile);
                System.out.println("Encryption successful!");
            } else if ("decrypt-file".equals(action)) {
                // Decrypt the file
                // Assuming we have the secret key used during encryption
                SecretKey key = KeyManager.generateKey(); // You should use the same key from encryption

                drm.decryptContent(inputFile, key);
                System.out.println("Decryption successful!");
            } else {
                System.err.println("Unknown action: " + action);
                System.exit(1);
            }
        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println(action + " failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
