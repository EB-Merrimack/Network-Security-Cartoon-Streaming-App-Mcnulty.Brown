package common.Video_Security.Decryption;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import common.CryptoUtils;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

/**
 * Handles decryption of AES-encrypted video or content files using a provided Base64-encoded AES key and IV.
 * 
 * This class is responsible for:
 *     Decoding the AES key and IV from Base64</li>
 *     Decrypting the contents of a given encrypted file</li>
 *     Saving the decrypted result to disk</li>
 */
public class Unprotector {

    private final SecretKey aesKey; //The AES secret key used for decryption
    private final byte[] aesIV;// The initialization vector used for AES decryption.


    /**
     * Constructs a new {@code Unprotector} instance with the given AES key and IV.
     *
     * @param base64AESKey The AES key encoded in Base64.
     * @param encryptedFile The encrypted file (used here for logging).
     * @param base64IV The initialization vector encoded in Base64.
     * @throws Exception if the key or IV cannot be decoded.
     */
    public Unprotector(String base64AESKey, File encryptedFile, String base64IV) throws Exception {
        System.out.println("[DEBUG] Starting Unprotector with base64AESKey: " + base64AESKey );
        System.out.println("[DEBUG] Initializing Unprotector...");
        byte[] aesKeyBytes = Base64.getDecoder().decode(base64AESKey);
        System.out.println("[DEBUG] AES key decoded successfully.");
        this.aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        this.aesIV = Base64.getDecoder().decode(base64IV);
    }

    /**
     * Decrypts the contents of the given encrypted file using the AES key and IV provided at construction.
     * The decrypted file is saved to the same directory with the ".enc" extension removed or ".decrypted" appended.
     *
     * @param encryptedFile The encrypted file to be decrypted.
     * @return The path to the decrypted output file.
     * @throws Exception if the file does not exist or decryption fails.
     */
    public Path unprotectContent(File encryptedFile) throws Exception {
        System.out.println("[DEBUG] Starting unprotection for file: " + encryptedFile.getAbsolutePath());
    
        if (!encryptedFile.exists()) {
            System.err.println("[ERROR] Encrypted file does not exist: " + encryptedFile.getAbsolutePath());
            throw new Exception("Encrypted file not found: " + encryptedFile.getAbsolutePath());
        }
    
        byte[] encryptedData = Files.readAllBytes(encryptedFile.toPath());
        System.out.println("[DEBUG] Encrypted file read. Size: " + encryptedData.length + " bytes");
    
        // No IV extraction! The whole file is ciphertext
        System.out.println("[DEBUG] Decrypting content using provided AES IV...");
        byte[] decryptedContent = CryptoUtils.decrypt(encryptedData, aesKey, aesIV);
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
        return outputPath;
    }
    
}
