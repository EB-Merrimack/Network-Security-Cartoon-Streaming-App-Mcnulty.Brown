package common.Video_Security.Decryption;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import server.Configuration;
import common.CryptoUtils;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

public class Unprotector {

    private final SecretKey aesKey;
    private final byte[] aesIV;      // IV ready to use
    
    public Unprotector(String base64AESKey, String base64IV) {
        byte[] aesKeyBytes = Base64.getDecoder().decode(base64AESKey);
        this.aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        this.aesIV = Base64.getDecoder().decode(base64IV);
    }

    public void unprotectContent(File encryptedFile) throws Exception {
        byte[] encryptedData = Files.readAllBytes(encryptedFile.toPath());
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

        System.out.println("Decrypted content saved to: " + outputPath.toAbsolutePath());
    }
}
