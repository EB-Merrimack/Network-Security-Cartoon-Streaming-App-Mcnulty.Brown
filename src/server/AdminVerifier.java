package server;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AdminVerifier {

    private static final String FILE_PATH = "src/server/admin.json";
    private static final String HASH_PATH = "src/server/admin.json.sha256";

    public static boolean verifyAdminFile() {
        try {
            byte[] fileBytes = Files.readAllBytes(new File(FILE_PATH).toPath());

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(fileBytes);
            String computedHash = Base64.getEncoder().encodeToString(hashBytes);

            String storedHash = new String(Files.readAllBytes(new File(HASH_PATH).toPath())).trim();

            return computedHash.equals(storedHash);
        } catch (IOException | NoSuchAlgorithmException e) {
            System.err.println("Verification failed: " + e.getMessage());
            return false;
        }
    }
}
