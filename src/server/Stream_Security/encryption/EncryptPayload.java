package server.Stream_Security.encryption;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.*;

/*
 * This code is adapted from:
 *   https://github.com/alesordo/Secure-RTSP-Video-Streaming
 * 
 * Original project: Secure RTSP Video Streaming (by Alessandro Sordo)
 * Licensed under the MIT License.
 * 
 * Modifications:
 */

 public class EncryptPayload {

    public byte[] encrypt(byte[] data, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12]; // GCM standard IV size
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv); // 128-bit auth tag
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);

        byte[] cipherText = cipher.doFinal(data);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(ByteBuffer.allocate(4).putInt(cipherText.length).array()); // prefix ciphertext length
        outputStream.write(iv); // prepend IV
        outputStream.write(cipherText);

        return outputStream.toByteArray();
    }

    public byte[] decrypt(byte[] input, SecretKey aesKey) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(input);
        int ctLength = buffer.getInt(); // read length
        byte[] iv = new byte[12];
        buffer.get(iv);

        byte[] cipherText = new byte[ctLength];
        buffer.get(cipherText);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);

        return cipher.doFinal(cipherText);
    }
}