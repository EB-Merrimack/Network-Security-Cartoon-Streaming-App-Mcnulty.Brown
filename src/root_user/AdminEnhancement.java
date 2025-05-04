package root_user;

// This class is to be used for taking a user's existing account and encrypting it with the admin key
// to make it more secure to then be used in the admin.json for the root admin account
/* In production, this would be encrypted itself or deleted and not accessible in any way 
   to allow enhanced security for the super user */

/* To compile, run in terminal: ava -jar .\dist\root_user.jar after compiling the root_user using the compile and dist build */

import merrimackutil.json.types.JSONObject;
import server.Admin.Admin;
import merrimackutil.json.JSONSerializable;
import merrimackutil.json.JsonIO;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

public class AdminEnhancement {

    // The path for storing the admin JSON file and its SHA-256 hash
    private static final String FILE_PATH = "src/server/Admin/admin.json";
    private static final String HASH_PATH = "src/server/Admin/admin.json.sha256";

    public static void main(String[] args) {
        try {
            // Create the admin data JSONObject, containing secure, encrypted data for the root admin account
            Admin adminData = new Admin();
            adminData.put("encryptedAESKey", "WxwosOa7VCuYn10dii+OnifHGewE8yO9bKgtWScktvGaP4SjBGiFXoQ4IFP01hPhOrGARhcitofi9COP8iG5O5lqwhd3sf7Bq9V6mkWS33zYT8+S8lf3uOAQ0ZUNwVJjWXDPSXbjvBJLT3oJdNPH0SMUmz9t8pBSWpNgjKBXwog=");
            adminData.put("salt", "TS0CrZgpODsqSwbLfztUjw==");
            adminData.put("pass", "AEF+YKYSnOdoU9Dgi6Cfig==");
            adminData.put("totp-key", "hL2agdNt2STM/V6MScIGUetbpfK96sEmRPPLGgJ2gUJtrJhkBDY2A/Kh2RrWSGrJJL3D7rXHeWpHlApCXDUJsA==");
            adminData.put("aesIV", "zOIwLu0fidM2DogQ");
            adminData.put("user", "eb_yes2025yay5");
            adminData.put("pubkey", "MIHYMIGQBgYrDgcCAQEwgYUCQQD8poLOjhLKuibvzPcRDlJtsHiwXt7LzR60ogjzrhYXrgHzW5Gkfm32NBPF4S7QiZvNEyrNUNmRUb3EPuc3WS4XAkBnhHGyepz0TukaScUUfbGpqvJE8FpDTWSGkx0tFCcbnjUDC3H9c9oXkGmzLik1Yw4cIGI1TQ2iCmxBblC+eUykA0MAAkA4o5p4br1Z8e8t95DFiZkw33YHCPsWwSYQZuhnDSIcMUDyz/buZEveo7hvAfztmBOJRH+VpsHiDiiYClT/uOg1");

            // Write the JSON data securely to the admin.json file using JsonIO
            writeSecureJsonFile(adminData);

            // Compute the SHA-256 hash of the admin.json file and write it to admin.json.sha256
            String hash = computeSHA256(FILE_PATH);
            writeHashFile(hash);

            System.out.println("admin.json and admin.json.sha256 created securely at src/server/");

        } catch (Exception e) {
            System.err.println("Failed to create secure admin.json:");
            e.printStackTrace();
        }
    }

    // Method to write the JSON object securely to a file using JsonIO
    private static void writeSecureJsonFile(Admin adminData) throws IOException {
        File file = new File(FILE_PATH);
        file.getParentFile().mkdirs(); // Ensure parent directories are created

        // Write the formatted JSON object into the file using JsonIO
        JsonIO.writeFormattedObject(adminData, file);

        // Set the file to read-only to ensure security
        setFileReadOnly(file);
    }

    // Method to compute the SHA-256 hash of the given file
    private static String computeSHA256(String filePath) throws IOException, NoSuchAlgorithmException {
        byte[] fileBytes = Files.readAllBytes(new File(filePath).toPath());

        // Create a SHA-256 digest
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(fileBytes);

        // Return the Base64 encoded hash
        return Base64.getEncoder().encodeToString(hashBytes);
    }

    // Method to write the computed SHA-256 hash to a file
    private static void writeHashFile(String hash) throws IOException {
        File hashFile = new File(HASH_PATH);

        // Write the computed SHA-256 hash to a file
        try (FileWriter writer = new FileWriter(hashFile)) {
            writer.write(hash);
        }

        // Set the hash file to read-only for security
        setFileReadOnly(hashFile);
    }

    // Method to set the file's permissions to read-only
    private static void setFileReadOnly(File file) throws IOException {
        if (!file.exists()) {
            throw new IOException("File not found: " + file.getAbsolutePath());
        }

        // Attempt to set the file to read-only
        if (!file.setReadOnly()) {
            System.err.println("Warning: Failed to mark " + file.getName() + " as read-only using standard method.");
        }

        try {
            // Set POSIX permissions if supported
            Set<PosixFilePermission> perms = new HashSet<>();
            perms.add(PosixFilePermission.OWNER_READ);
            Files.setPosixFilePermissions(file.toPath(), perms);
        } catch (UnsupportedOperationException e) {
            System.err.println("POSIX permissions not supported. Skipping...");
        }
    }
}
