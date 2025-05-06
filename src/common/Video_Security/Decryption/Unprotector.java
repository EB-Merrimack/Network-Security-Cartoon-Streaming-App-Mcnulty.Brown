package common.Video_Security.Decryption;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import server.Configuration;
import common.CryptoUtils;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;

public class Unprotector {

    private final SecretKey aesKey;

    public Unprotector(String base64AESKey, File encryptedFile) throws Exception {
        System.out.println("[DEBUG] Starting Unprotector with base64AESKey: " + base64AESKey );
        System.out.println("[DEBUG] Initializing Unprotector...");
        byte[] aesKeyBytes = Base64.getDecoder().decode(base64AESKey);
        System.out.println("[DEBUG] AES key decoded successfully.");
        this.aesKey = new SecretKeySpec(aesKeyBytes, "AES");


        unprotectContent(encryptedFile);
    }

    public void unprotectContent(File encryptedFile) throws Exception {
        System.out.println("[DEBUG] Starting unprotection for file: " + encryptedFile.getAbsolutePath());
    
        if (!encryptedFile.exists()) {
            System.err.println("[ERROR] Encrypted file does not exist: " + encryptedFile.getAbsolutePath());
            throw new Exception("Encrypted file not found: " + encryptedFile.getAbsolutePath());
        }
    
        byte[] encryptedData = Files.readAllBytes(encryptedFile.toPath());
        System.out.println("[DEBUG] Encrypted file read. Size: " + encryptedData.length + " bytes");
    
        // Extract IV and ciphertext
        byte[] iv = Arrays.copyOfRange(encryptedData, 0, 12);
        byte[] ciphertext = Arrays.copyOfRange(encryptedData, 12, encryptedData.length);
        System.out.println("[DEBUG] IV extracted. Length: " + iv.length + " bytes");
        System.out.println("[DEBUG] Ciphertext extracted. Length: " + ciphertext.length + " bytes");
    
        System.out.println("[DEBUG] Decrypting content...");
        byte[] decryptedContent = CryptoUtils.decrypt(ciphertext, aesKey);
        System.out.println("[DEBUG] Content decrypted successfully. Size: " + decryptedContent.length + " bytes");
    
        // Save the decrypted file
        String originalName = encryptedFile.getName();
        if (originalName.endsWith(".enc")) {
            originalName = originalName.substring(0, originalName.length() - 4);
            System.out.println("[DEBUG] Stripped '.enc' extension. New filename: " + originalName);
        } else {
            originalName = originalName + ".decrypted";
            System.out.println("[DEBUG] Appending '.decrypted' to filename. New filename: " + originalName);
        }
    
        Path outputPath = encryptedFile.getParentFile().toPath().resolve(originalName);
        System.out.println("[DEBUG] Writing decrypted content to: " + outputPath.toAbsolutePath());
    
        Files.write(outputPath, decryptedContent);
    
        System.out.println("[SERVER] Decrypted content saved successfully to: " + outputPath.toAbsolutePath());
    }
    
}
