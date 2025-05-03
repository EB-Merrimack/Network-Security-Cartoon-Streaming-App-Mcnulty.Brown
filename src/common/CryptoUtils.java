package common;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.util.Base64;

public class CryptoUtils {

    // GCM settings
    private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH_BITS = 128; // Auth tag 128 bits (16 bytes)

    /**
     * Encrypts the fileData using AES-GCM with provided key and IV.
     */
    public static byte[] encrypt(byte[] fileData, SecretKey key, byte[] aesIV) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, aesIV);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        return cipher.doFinal(fileData);
    }

    /**
     * Decrypts the encryptedData using AES-GCM with provided key and IV.
     */
    public static byte[] decrypt(byte[] encryptedData, SecretKey key, byte[] aesIV) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, aesIV);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(encryptedData);  // MAC checked automatically
    }

    public static String encodeBase64(byte[] encoded) {
        return Base64.getEncoder().encodeToString(encoded);
    }
}
