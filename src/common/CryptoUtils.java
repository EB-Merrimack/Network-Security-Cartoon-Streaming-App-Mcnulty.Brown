package common;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

public class CryptoUtils {

    private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int IV_SIZE = 12; // Standard IV size for AES-GCM

    /**
     * Encrypts data using AES-GCM and returns IV + ciphertext.
     */
    public static byte[] encrypt(byte[] data, SecretKey key) throws Exception {
        byte[] iv = generateIV();
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
    
        byte[] encryptedData = cipher.doFinal(data);
    
        // Combine IV + encrypted data (which includes the tag)
        byte[] result = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encryptedData, 0, result, iv.length, encryptedData.length);
    
        return result;
    }
    
    /**
     * Decrypts data using AES-GCM and returns the original plaintext.
     */
    public static byte[] decrypt(byte[] encryptedData, SecretKey key) throws Exception {
        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(encryptedData, 0, iv, 0, IV_SIZE);
    
        byte[] ciphertext = new byte[encryptedData.length - IV_SIZE];
        System.arraycopy(encryptedData, IV_SIZE, ciphertext, 0, ciphertext.length);
    
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
    
        return cipher.doFinal(ciphertext);
    }
    
    /**
     * Generates a random IV.
     */
    private static byte[] generateIV() {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static PublicKey decodeElGamalPublicKey(byte[] decode) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'decodeElGamalPublicKey'");
    }
}
