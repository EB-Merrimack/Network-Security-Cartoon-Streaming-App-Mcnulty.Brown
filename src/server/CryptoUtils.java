package server;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.util.Base64;

public class CryptoUtils {

    public static byte[] encrypt(byte[] fileData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES"); // Later: switch to AES/GCM or AES/CBC
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(fileData);
    }

    /**
     * Decrypts the given encrypted data using the specified secret key with AES algorithm.
     *
     * @param encryptedData the data to be decrypted
     * @param key the secret key used for decryption
     * @return the decrypted data as a string
     * @throws Exception if an error occurs during decryption
     */
    public static String decrypt(byte[] encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(encryptedData));
    }

    public static String encodeBase64(byte[] encoded) {
        return Base64.getEncoder().encodeToString(encoded);
    }
}
