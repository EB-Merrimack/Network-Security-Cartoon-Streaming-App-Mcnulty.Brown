package root_user;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Base64;

    /**
     * Main method that generates an AES key and a random IV, then prints their Base64 encoded values to the console.
     * 
     * @param args Command-line arguments (unused).
     * @throws Exception if an error occurs while generating the key or IV.
     */
    public class AESKeyGen {
    public static void main(String[] args) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // 128-bit AES
        SecretKey key = keyGen.generateKey();

        byte[] iv = new byte[12]; // 12-byte IV for GCM
        new SecureRandom().nextBytes(iv);

        String base64Key = Base64.getEncoder().encodeToString(key.getEncoded());
        String base64IV = Base64.getEncoder().encodeToString(iv);

        System.out.println("AES Key: " + base64Key);
        System.out.println("AES IV: " + base64IV);
    }
}