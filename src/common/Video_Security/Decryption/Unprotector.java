package common.Video_Security.Decryption;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import common.CryptoUtils;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

public class Unprotector {

    private final SecretKey aesKey;
    private final byte[] aesIV;

    public Unprotector(String base64AESKey, File encryptedFile, String base64IV) throws Exception {
        byte[] aesKeyBytes = Base64.getDecoder().decode(base64AESKey);
        this.aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        this.aesIV = Base64.getDecoder().decode(base64IV);

    
    }

    public Path unprotectContent(File encryptedFile) throws Exception {
    
        if (!encryptedFile.exists()) {
            System.err.println("[ERROR] Encrypted file does not exist: " + encryptedFile.getAbsolutePath());
            throw new Exception("Encrypted file not found: " + encryptedFile.getAbsolutePath());
        }
    
        byte[] encryptedData = Files.readAllBytes(encryptedFile.toPath());
    
        //The whole file is ciphertext
        byte[] decryptedContent = CryptoUtils.decrypt(encryptedData, aesKey, aesIV);
    
        // Save the decrypted file
        String originalName = encryptedFile.getName();
        if (originalName.endsWith(".enc")) {
            originalName = originalName.substring(0, originalName.length() - 4);
        } else {
            originalName = originalName + ".decrypted";
        }
    
        Path outputPath = encryptedFile.getParentFile().toPath().resolve(originalName);
    
        Files.write(outputPath, decryptedContent);
    
        System.out.println("[SERVER] Decrypted content saved successfully to: " + outputPath.toAbsolutePath());
        return outputPath;
    }
    
}
