package common.protocol.user_creation;

import common.protocol.messages.StatusMessage;
import common.protocol.user_auth.UserDatabase;

import org.bouncycastle.crypto.generators.SCrypt;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class CreateAccount {

    // Simulated database (in a real-world scenario, this could be a database connection)
    private static Map<String, User> userDatabase = new HashMap<>();

    // Internal User class
    public static class User {
        private String username;
        private String passwordHash; // Store password securely using hash
        private String publicKey;
        private String totpKey;       // Base64 encoded TOTP key
        private String privateKey;    // The private key generated for the user
        private String encryptedAESKey; // AES key encrypted with user's public key
        private String aesIV;           // Initialization Vector for AES

        // Constructor
        public User(String username, String passwordHash, String publicKey,
                    String totpKey, String privateKey, String encryptedAESKey, String aesIV) {
            this.username = username;
            this.passwordHash = passwordHash;
            this.publicKey = publicKey;
            this.totpKey = totpKey;
            this.privateKey = privateKey;
            this.encryptedAESKey = encryptedAESKey;
            this.aesIV = aesIV;
        }
    }

    /**
     * Creates a new user in the user database given a username, password, public key,
     * encrypted AES key, AES IV, and private key.
     *
     * @param username         the username of the new user
     * @param password         the password of the new user
     * @param publicKey        the encoded public key of the new user
     * @param encryptedAESKey  the AES key encrypted with the user's public key
     * @param aesIV            the initialization vector (IV) used with AES
     * @param privateKey       the private key associated with the user
     * @return a StatusMessage with success/failure and the base64 TOTP key or error message
     */
    public static StatusMessage createAccount(String username, String password, String publicKey, String encryptedAESKey, String aesIV, String userfile ) {
        try {
            // Check if user already exists
            if (userDatabase.containsKey(username)) {
                return new StatusMessage(false, "User already exists.");
            }

            // Generate salt
            byte[] saltBytes = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(saltBytes);
            String salt = Base64.getEncoder().encodeToString(saltBytes);

            // Hash password using SCrypt
            byte[] hash = SCrypt.generate(password.getBytes(), saltBytes, 2048, 8, 1, 16);
            String passwordHash = Base64.getEncoder().encodeToString(hash);

            // Generate TOTP key
            byte[] totpKeyBytes = new byte[64]; // 512 bits
            random.nextBytes(totpKeyBytes);
            String totpKey = Base64.getEncoder().encodeToString(totpKeyBytes);

            // Create User object
            common.protocol.user_auth.User user = new  common.protocol.user_auth.User(
                salt,
                username,
                passwordHash,
                publicKey,
                totpKey,
                encryptedAESKey,
                aesIV

            );

              // Save user to database and write back to file
            UserDatabase.put(username, user);
            UserDatabase.save(userfile);

            // Return the TOTP key (for client setup)
            return new StatusMessage(true, totpKey);

        } catch (Exception e) {
            e.printStackTrace();
            return new StatusMessage(false, "Unexpected error during account creation.");
        }
    }

   
}
