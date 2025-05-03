package server.Stream_Security;

import javax.crypto.SecretKey;

import server.Stream_Security.encryption.EncryptPayload;

import java.io.ByteArrayOutputStream;
import java.net.*;
import java.nio.ByteBuffer;

import static java.util.Arrays.copyOfRange;
/*
 * This code is adapted from:
 *   https://github.com/alesordo/Secure-RTSP-Video-Streaming
 * 
 * Original project: Secure RTSP Video Streaming (by Alessandro Sordo)
 * Licensed under the MIT License.
 * 
 * Modifications:
 */
public class SRTS extends DatagramSocket {
    public SRTS() throws SocketException {
        super();
    }
    public SRTS(SocketAddress bindaddr) throws SocketException {
        super(bindaddr);
    }
    public void mySend(DatagramPacket p, byte[] buff, int ptSize, SecretKey key, SecretKey hMacKey, String algorithm) throws Exception {
        byte[] fixedheader = {0b00010000};

        //Encryption here
        EncryptPayload encryptPayload = new EncryptPayload();
        byte[] encryptedPayload = encryptPayload.encrypt(buff,key);

        //Merging everything
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.write(fixedheader);
        outputStream.write(encryptedPayload);
        byte[] frame = outputStream.toByteArray();

        p.setData(frame, 0, frame.length);
        super.send(p);
    }
    public byte[] myReceive(DatagramPacket inPacket, SecretKey key, SecretKey hMacKey, String algorithm) throws Exception {
        super.receive(inPacket);

        //Get the full packet
        byte[] packet = inPacket.getData();

        byte[] encryptedBuff = java.util.Arrays.copyOfRange(packet, 1, packet.length);

        //Decription here
        EncryptPayload encryptPayload = new EncryptPayload();
        return encryptPayload.decrypt(encryptedBuff,key);
    }
}
