package common.protocol.user_creation;

import common.protocol.Message;
import common.protocol.messages.StatusMessage;
import common.protocol.user_auth.User;
import common.protocol.user_auth.UserDatabase;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;

import org.bouncycastle.crypto.generators.SCrypt;

import java.io.InvalidObjectException;
import java.security.SecureRandom;
import java.util.Base64;

public class CreateAccount implements Message {
    public static StatusMessage createAccount(
        String username, 
        String password, 
        String publicKey, 
        String encryptedAESKey, 
        String aesIV,
        String userfile
    ) {
        try {
            // Load users.json
            UserDatabase.load(userfile);

            if (UserDatabase.containsKey(username)) {
                return new StatusMessage(false, "User already exists.");
            }

            // Generate salt + hash password
            byte[] saltBytes = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(saltBytes);
            String salt = Base64.getEncoder().encodeToString(saltBytes);

            byte[] hash = SCrypt.generate(password.getBytes(), saltBytes, 2048, 8, 1, 16);
            String passwordHash = Base64.getEncoder().encodeToString(hash);

            // Generate TOTP key
            byte[] totpKeyBytes = new byte[64];
            random.nextBytes(totpKeyBytes);
            String totpKey = Base64.getEncoder().encodeToString(totpKeyBytes);

            // Build user object
            User newUser = new User(
                salt,
                passwordHash,
                totpKey,
                username,
                publicKey,
                encryptedAESKey,
                aesIV
            );

            // Save to database
            UserDatabase.put(username, newUser);
            UserDatabase.save(userfile);

            // Return TOTP for client setup
            return new StatusMessage(true, totpKey);

        } catch (Exception e) {
            e.printStackTrace();
            return new StatusMessage(false, "Account creation failed.");
        }
    }

    public String getUsername() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getUsername'");
    }

    public String getPassword() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getPassword'");
    }

    public String getPublicKey() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getPublicKey'");
    }

    public String getEncryptedAESKey() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getEncryptedAESKey'");
    }

    public String getAesIV() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getAesIV'");
    }

    @Override
    public void deserialize(JSONType arg0) throws InvalidObjectException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'deserialize'");
    }

    @Override
    public JSONType toJSONType() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'toJSONType'");
    }

    @Override
    public String getType() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getType'");
    }

    @Override
    public Message decode(JSONObject obj) throws InvalidObjectException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'decode'");
    }
}