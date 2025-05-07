package common;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.PublicKey;
import java.security.Security;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;

import java.util.Arrays;

/**
 * Utility class providing cryptographic operations including AES-GCM encryption/decryption
 * and decoding ElGamal public keys from ASN.1 format.
 */
public class CryptoUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final int IV_SIZE = 12; // 96 bits, standard for GCM
    private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH_BITS = 128; // 16 bytes authentication tag
    private static final int DEBUG_MAX_BYTES = 128; // Max bytes shown in debug output

    /**
     * Decodes an ElGamal public key from its raw ASN.1 encoded byte format.
     *
     * @param encoded the ASN.1-encoded byte array containing the ElGamal public key
     * @return the reconstructed {@link PublicKey} instance
     * @throws Exception if decoding fails due to invalid structure or algorithm errors
     */
    public static PublicKey decodeElGamalPublicKey(byte[] encoded) throws Exception {
        try (ASN1InputStream asn1InputStream = new ASN1InputStream(encoded)) {
            ASN1Sequence sequence = (ASN1Sequence) asn1InputStream.readObject();
            ASN1Integer p = (ASN1Integer) sequence.getObjectAt(0);
            ASN1Integer g = (ASN1Integer) sequence.getObjectAt(1);
            ASN1Integer y = (ASN1Integer) sequence.getObjectAt(2);

            // Validate structure (not used directly)
            p.getValue();
            g.getValue();
            y.getValue();

            KeyFactory keyFactory = KeyFactory.getInstance("ElGamal", "BC");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new Exception("Error decoding ElGamal public key: " + e.getMessage(), e);
        }
    }

/**
     * Encrypts the provided plaintext using AES in GCM mode with the given key and IV.
     *
     * @param data the plaintext data to encrypt
     * @param key the AES secret key
     * @param iv the initialization vector (IV), must be 12 bytes
     * @return the encrypted ciphertext including the authentication tag
     * @throws Exception if encryption fails
     */
    public static byte[] encrypt(byte[] data, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION, "BC");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        System.out.println("[DEBUG] Encrypting...");
        debugBytes("Plaintext", data);
        debugBytes("IV", iv);

        byte[] encryptedData = cipher.doFinal(data);

        // Return just the ciphertext + tag (no IV included)
        return encryptedData;
    }

/**
     * Decrypts AES-GCM encrypted data using the given key and IV.
     *
     * @param encryptedData the encrypted data including the GCM authentication tag
     * @param key the AES secret key
     * @param iv the initialization vector (IV), must match the one used in encryption
     * @return the decrypted plaintext
     * @throws SecurityException if the authentication tag is invalid (tampering detected)
     * @throws Exception if decryption fails due to other reasons
     */
    public static byte[] decrypt(byte[] encryptedData, SecretKey key, byte[] iv) throws Exception {
        if (encryptedData.length < (GCM_TAG_LENGTH_BITS / 8)) {
            throw new IllegalArgumentException("Encrypted data too short to contain authentication tag.");
        }

        System.out.println("[DEBUG] Decrypting...");
        debugBytes("Encrypted input", encryptedData);
        debugBytes("IV", iv);

        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION, "BC");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        try {
            byte[] plaintext = cipher.doFinal(encryptedData);
            System.out.println("[DEBUG] Decryption successful.");
            debugBytes("Plaintext", plaintext);
            return plaintext;
        } catch (AEADBadTagException e) {
            System.err.println("[ERROR] Decryption failed: authentication tag mismatch!");
            throw new SecurityException("Decryption failed: authentication tag mismatch.", e);
        } catch (Exception e) {
            System.err.println("[ERROR] Decryption failed: " + e.getMessage());
            throw new Exception("Decryption failed unexpectedly: " + e.getMessage(), e);
        }
    }

   

/**
     * Helper method to print debug output of a byte array in hexadecimal, truncated if too long.
     *
     * @param label a label to identify the data being printed
     * @param bytes the byte array to print
     */
    private static void debugBytes(String label, byte[] bytes) {
        int length = bytes.length;
        System.out.println("[DEBUG] " + label + ": " + length + " bytes");
        if (length <= DEBUG_MAX_BYTES) {
            System.out.println(bytesToHex(bytes));
        } else {
            System.out.println(bytesToHex(Arrays.copyOf(bytes, DEBUG_MAX_BYTES)) + "... [truncated]");
        }
    }

/**
     * Converts a byte array to a hexadecimal string.
     *
     * @param bytes the byte array to convert
     * @return a hexadecimal string representation of the byte array
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
