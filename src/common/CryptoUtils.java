package common;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CryptoUtils {

    // GCM settings
    private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH_BITS = 128; // Auth tag 128 bits (16 bytes)

    /**
     * Encrypts the fileData using AES-GCM with provided key and IV.
     * Returns a byte array containing the IV + ciphertext + authentication tag.
     */
    public static byte[] encrypt(byte[] fileData, SecretKey key, byte[] aesIV) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, aesIV);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        byte[] encryptedData = cipher.doFinal(fileData);
        byte[] tag = new byte[16];
        System.arraycopy(encryptedData, encryptedData.length - 16, tag, 0, 16);
        byte[] ciphertext = new byte[encryptedData.length - 16];
        System.arraycopy(encryptedData, 0, ciphertext, 0, ciphertext.length);

        // Combine IV + ciphertext + tag
        byte[] result = new byte[aesIV.length + ciphertext.length + tag.length];
        System.arraycopy(aesIV, 0, result, 0, aesIV.length);
        System.arraycopy(ciphertext, 0, result, aesIV.length, ciphertext.length);
        System.arraycopy(tag, 0, result, aesIV.length + ciphertext.length, tag.length);

        return result;
    }

    /**
     * Decrypts the encryptedData using AES-GCM with provided key and IV.
     * Verifies the authentication tag.
     */
    public static byte[] decrypt(byte[] encryptedData, SecretKey key, byte[] aesIV) throws Exception {
        // Extract the tag and ciphertext from the input data
        byte[] tag = new byte[16];
        System.arraycopy(encryptedData, encryptedData.length - 16, tag, 0, 16);
        byte[] ciphertext = new byte[encryptedData.length - 16];
        System.arraycopy(encryptedData, 0, ciphertext, 0, ciphertext.length);

        // Decrypt the ciphertext
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, aesIV);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        // Perform decryption and verify the tag automatically
        return cipher.doFinal(ciphertext);  // MAC checked automatically by AES-GCM
    }

    public static String encodeBase64(byte[] encoded) {
        return Base64.getEncoder().encodeToString(encoded);
    }

     public static PublicKey decodeElGamalPublicKey(byte[] encodedKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("ElGamal", new BouncyCastleProvider());
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
        return keyFactory.generatePublic(keySpec);
    }
}
