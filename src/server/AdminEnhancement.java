package server;
//This class is to be used for taking a users existing account and encrypting it with the admin key to make it more secure 
//to then be used in the admin.json the root admin account
/* in production this would be encrypted itself and not accessible in any way to allowed enhanced security for the super user*/

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.io.*;
import merrimackutil.json.types.JSONObject;

public class AdminEnhancement {

    private static final String ADMIN_KEY = "YOUR_ADMIN_KEY"; // Admin key for encryption
    private static final String SIGNING_KEY = "YOUR_SIGNING_PRIVATE_KEY"; // Private key for signing
    private static final String FILE_PATH = "admin.json"; // Path where the encrypted data will be stored

    public static void main(String[] args) {
        // Example usage: Encrypt a user account
        String userAccountJson = "{ \"username\": \"admin\", \"password\": \"securepassword123\" }";
        String encryptedAccount = encryptUserAccount(userAccountJson);
        
        String signature = generateSignature(encryptedAccount); // Generate signature

        // Store encrypted account and its signature in the file
        storeEncryptedAccount(encryptedAccount, signature);
    }

    // Method to encrypt a user account
    public static String encryptUserAccount(String userAccountJson) {
        try {
            // Convert the admin key to SecretKey
            SecretKeySpec secretKey = new SecretKeySpec(ADMIN_KEY.getBytes(), "AES");

            // Create Cipher instance for AES encryption
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            // Encrypt the user account JSON string
            byte[] encryptedBytes = cipher.doFinal(userAccountJson.getBytes());

            // Return the encrypted data as a base64 encoded string
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // Method to generate a digital signature for the encrypted account data
    public static String generateSignature(String data) {
        try {
            // Load the private signing key (assuming it's in base64 format)
            PrivateKey privateKey = getPrivateKeyFromBase64(SIGNING_KEY);

            // Create Signature instance
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(data.getBytes());

            // Sign the data and return the signature as a base64 encoded string
            byte[] signedData = signature.sign();
            return Base64.getEncoder().encodeToString(signedData);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // Method to store the encrypted account and its signature in the admin.json file
    public static void storeEncryptedAccount(String encryptedAccount, String signature) {
        try {
            // Create a JSON object to store the encrypted account and its signature
            JSONObject json = new JSONObject();
            json.put("encrypted_account", encryptedAccount);
            json.put("signature", signature);

            // Write the JSON object to the admin.json file
            File file = new File(FILE_PATH);
            try (FileWriter fileWriter = new FileWriter(file)) {
                fileWriter.write(json.toString());
            }

            // Set the file as read-only to prevent modification
            file.setReadOnly();
            System.out.println("Encrypted account and signature stored in " + FILE_PATH);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Method to load a private key from a base64 encoded string
    private static PrivateKey getPrivateKeyFromBase64(String base64Key) throws GeneralSecurityException {
        byte[] decodedKey = Base64.getDecoder().decode(base64Key);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodedKey));
    }

    // Method to verify the signature
    public static boolean verifySignature(String data, String signature) {
        try {
            // Load the public key (this should be securely managed and stored)
            PublicKey publicKey = getPublicKeyFromBase64("YOUR_PUBLIC_KEY");

            // Create Signature instance
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(publicKey);
            sig.update(data.getBytes());

            // Verify the signature
            return sig.verify(Base64.getDecoder().decode(signature));
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    // Method to load a public key from a base64 encoded string
    private static PublicKey getPublicKeyFromBase64(String base64Key) throws GeneralSecurityException {
        byte[] decodedKey = Base64.getDecoder().decode(base64Key);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(decodedKey));
    }
}

