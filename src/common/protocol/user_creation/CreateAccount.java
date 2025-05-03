package common.protocol.user_creation;

import common.protocol.messages.StatusMessage;
import common.protocol.user_auth.User;
import common.protocol.user_auth.UserDatabase;

import org.bouncycastle.crypto.generators.SCrypt;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class CreateAccount {

    public static StatusMessage createAccount(String username, String password, String publicKey, String encryptedAESKey, String aesIV, String userfile) {
        try {
            // Load users from file
            UserDatabase.load(userfile);

            // Check if user already exists
            if (UserDatabase.containsKey(username)) {
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
            byte[] totpKeyBytes = new byte[64];
            random.nextBytes(totpKeyBytes);
            String totpKey = Base64.getEncoder().encodeToString(totpKeyBytes);

            // Create User object
            User user = new User(salt, passwordHash, totpKey, username, publicKey, encryptedAESKey, aesIV);

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