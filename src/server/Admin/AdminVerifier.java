package server.Admin;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Verifies the integrity of the admin.json file by comparing its SHA-256 hash with the stored hash.
 * This class ensures that the admin configuration file has not been tampered with by verifying the hash.
 */
public class AdminVerifier {

    
    private static final String HASH_PATH = "src/server/Admin/admin.json.sha256";

    /**
     * Verify the integrity of the admin.json file by comparing its SHA-256 hash with the stored hash.
     * 
     * @param adminFilePath the path to the admin.json file
     * @return true if the verification is successful, false otherwise
     */
    public static boolean verifyAdminFile(String adminFilePath) {
        try {
            // Read the admin.json file
            byte[] fileBytes = Files.readAllBytes(new File(adminFilePath).toPath());
    
            // Compute the SHA-256 hash of the file
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(fileBytes);
            String computedHash = Base64.getEncoder().encodeToString(hashBytes);
    
            // Read the stored hash from the file
            String storedHash = new String(Files.readAllBytes(new File(HASH_PATH).toPath())).trim();
    
            // Compare the computed hash with the stored hash
            if (computedHash.equals(storedHash)) {
                System.out.println("Verification successful.");
                return true;
            } else {
                System.err.println("Verification failed: Hash mismatch.");
                return false;
            }
    
        } catch (IOException | NoSuchAlgorithmException e) {
            System.err.println("Verification failed: " + e.getMessage());
            return false;
        }
    }
    
}
