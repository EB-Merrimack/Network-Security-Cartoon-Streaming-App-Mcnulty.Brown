package server.Video_Security.encryption;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import server.Configuration;
import common.CryptoUtils;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;

public class Protector {

    private final SecretKey aesKey;  // AES key ready to use
    private final byte[] aesIV;      // IV ready to use

    public Protector(String base64AESKey, String base64IV) {
        byte[] aesKeyBytes = Base64.getDecoder().decode(base64AESKey);
        this.aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        this.aesIV = Base64.getDecoder().decode(base64IV);
    }

    public void protectContent(File inputFile) throws Exception {
        byte[] fileData = Files.readAllBytes(inputFile.toPath());
        byte[] encryptedContent = CryptoUtils.encrypt(fileData, aesKey, aesIV);

        // Combine IV + encrypted content
        byte[] outputData = new byte[aesIV.length + encryptedContent.length];
        System.arraycopy(aesIV, 0, outputData, 0, aesIV.length);
        System.arraycopy(encryptedContent, 0, outputData, aesIV.length, encryptedContent.length);

        // Use configured video folder
        Path videoDir = Paths.get(Configuration.getVideofolder());
        if (!Files.exists(videoDir)) {
            Files.createDirectories(videoDir);
        }

        // Save the encrypted file with .enc extension
        String outputFileName = inputFile.getName() + ".enc";
        Path outputPath = videoDir.resolve(outputFileName);
        Files.write(outputPath, outputData);

        System.out.println("Encrypted content (IV + ciphertext) saved to: " + outputPath.toAbsolutePath());
    }
}
