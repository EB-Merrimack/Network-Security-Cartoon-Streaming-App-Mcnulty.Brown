package common;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.params.ElGamalPublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;

import java.util.Arrays;

public class CryptoUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final int IV_SIZE = 12; // 96 bits, standard for GCM
    private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH_BITS = 128; // 16 bytes
    private static final int DEBUG_MAX_BYTES = 128; // Max bytes shown in debug output

    // Decode an ElGamal public key from raw ASN.1 bytes
    public static PublicKey decodeElGamalPublicKey(byte[] encoded) throws Exception {
        try (ASN1InputStream asn1InputStream = new ASN1InputStream(encoded)) {
            ASN1Sequence sequence = (ASN1Sequence) asn1InputStream.readObject();
            ASN1Integer p = (ASN1Integer) sequence.getObjectAt(0);
            ASN1Integer g = (ASN1Integer) sequence.getObjectAt(1);
            ASN1Integer y = (ASN1Integer) sequence.getObjectAt(2);

            // (not used directly here, but parsed to validate structure)
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

    // Encrypt data using AES-GCM
    public static byte[] encrypt(byte[] data, SecretKey key) throws Exception {
        byte[] iv = generateIV();
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION, "BC");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        System.out.println("[DEBUG] Encrypting...");
        debugBytes("Plaintext", data);
        debugBytes("IV", iv);

        byte[] encryptedData = cipher.doFinal(data);

        System.out.println("[DEBUG] Encrypted (ciphertext + tag): total " + encryptedData.length + " bytes");

        byte[] result = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encryptedData, 0, result, iv.length, encryptedData.length);

        return result;
    }

    // Decrypt data using AES-GCM
    public static byte[] decrypt(byte[] encryptedData, SecretKey key) throws Exception {
        if (encryptedData.length < IV_SIZE + (GCM_TAG_LENGTH_BITS / 8)) {
            throw new IllegalArgumentException("Encrypted data too short to be valid AES-GCM ciphertext.");
        }

        System.out.println("[DEBUG] Decrypting...");
        debugBytes("Encrypted input", encryptedData);

        byte[] iv = Arrays.copyOfRange(encryptedData, 0, IV_SIZE);
        byte[] ciphertextWithTag = Arrays.copyOfRange(encryptedData, IV_SIZE, encryptedData.length);

        System.out.println("[DEBUG] IV extracted:");
        debugBytes("IV", iv);

        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION, "BC");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        try {
            byte[] plaintext = cipher.doFinal(ciphertextWithTag);
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

    // Generate a random IV
    private static byte[] generateIV() {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    // Helper: print limited debug bytes
    private static void debugBytes(String label, byte[] bytes) {
        int length = bytes.length;
        System.out.println("[DEBUG] " + label + ": " + length + " bytes");
        if (length <= DEBUG_MAX_BYTES) {
            System.out.println(bytesToHex(bytes));
        } else {
            System.out.println(bytesToHex(Arrays.copyOf(bytes, DEBUG_MAX_BYTES)) + "... [truncated]");
        }
    }

    // Helper: convert bytes to hex string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
