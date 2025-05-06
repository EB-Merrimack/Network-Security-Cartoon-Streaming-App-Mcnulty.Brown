package common;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.params.ElGamalPublicKeyParameters;
import org.bouncycastle.crypto.params.ElGamalKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.spec.GCMParameterSpec;

public class CryptoUtils {

    static {
        // Register BouncyCastle as the security provider
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final int IV_SIZE = 12; // Standard IV size for AES-GCM
    private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH_BITS = 128;

    /**
     * Decodes an ElGamal public key from a byte array.
     */
    public static PublicKey decodeElGamalPublicKey(byte[] decode) throws Exception {
        try {
            // ElGamal public key decoding
            ASN1InputStream asn1InputStream = new ASN1InputStream(decode);
            ASN1Sequence sequence = (ASN1Sequence) asn1InputStream.readObject();
            asn1InputStream.close();

            // Extract the components of the ElGamal public key: p, g, y
            ASN1Integer p = (ASN1Integer) sequence.getObjectAt(0); // Prime modulus
            ASN1Integer g = (ASN1Integer) sequence.getObjectAt(1); // Generator
            ASN1Integer y = (ASN1Integer) sequence.getObjectAt(2); // Public key element

            // Now you can use these values to construct the ElGamal public key parameters
            byte[] pBytes = p.getEncoded();
            byte[] gBytes = g.getEncoded();
            byte[] yBytes = y.getEncoded();

            // You could use these parameters to generate an ElGamal public key, but typically, you
            // would wrap them in an appropriate class such as ElGamalPublicKeyParameters for cryptographic operations.
            
            // Returning a KeyFactory-based public key (simplified)
            KeyFactory keyFactory = KeyFactory.getInstance("ElGamal");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decode);
            return keyFactory.generatePublic(keySpec);

        } catch (Exception e) {
            throw new Exception("Error decoding ElGamal public key: " + e.getMessage(), e);
        }
    }

    /**
     * Encrypts data using AES-GCM and returns IV + ciphertext.
     */
    public static byte[] encrypt(byte[] data, javax.crypto.SecretKey key) throws Exception {
        byte[] iv = generateIV();
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(AES_TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key, spec);
        
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
    public static byte[] decrypt(byte[] encryptedData, javax.crypto.SecretKey key) throws Exception {
        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(encryptedData, 0, iv, 0, IV_SIZE);
        
        byte[] ciphertext = new byte[encryptedData.length - IV_SIZE];
        System.arraycopy(encryptedData, IV_SIZE, ciphertext, 0, ciphertext.length);
        
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(AES_TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key, spec);
        
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
}
