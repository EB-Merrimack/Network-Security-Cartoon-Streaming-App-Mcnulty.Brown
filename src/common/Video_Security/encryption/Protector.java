package common.Video_Security.encryption;

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

    public Protector(String base64EncryptedAESKey, String base64IV) throws Exception {
        // Decode the encrypted AES key from Base64
        byte[] decryptedAESKeyBytes = Base64.getDecoder().decode(base64EncryptedAESKey);
        
       
        // Now create a proper AES SecretKey
        this.aesKey = new SecretKeySpec(decryptedAESKeyBytes, "AES");

        // Decode the IV normally
        this.aesIV = Base64.getDecoder().decode(base64IV);
    }

    /**
     * Encrypts the input file and saves it.
     * @param inputFile The file to encrypt.
     * @return The Path where the encrypted file was saved.
     * @throws Exception if something goes wrong.
     */
    public Path protectContent(File inputFile) throws Exception {
        byte[] fileData = Files.readAllBytes(inputFile.toPath());
        byte[] encryptedContent = CryptoUtils.encrypt(fileData, aesKey, aesIV);

   
        // Use configured video folder
        Path videoDir = Paths.get(Configuration.getVideofolder());
        if (!Files.exists(videoDir)) {
            Files.createDirectories(videoDir);
        }

        // Save the encrypted file with .enc extension
        String outputFileName = inputFile.getName() + ".enc";
        Path outputPath = videoDir.resolve(outputFileName);
        Files.write(outputPath, encryptedContent);

        System.out.println("Encrypted content (IV + ciphertext) saved to: " + outputPath.toAbsolutePath());
        return outputPath;
    }
}
