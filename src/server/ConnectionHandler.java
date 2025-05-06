
package server;

import java.io.File;
import java.io.IOException;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Base64.Decoder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import server.Configuration;
import server.Admin.Admin;
import server.Admin.AdminAuthenticator;
import server.Admin.AdminAuthenticator;
import server.Admin.AdminVerifier;
import server.Video.Video;
import server.Video.videodatabase;
import common.CryptoUtils;
import common.Video_Security.Decryption.Unprotector;
import common.Video_Security.encryption.Protector;
import common.protocol.Message;
import common.protocol.user_creation.CreateAccount;
import common.protocol.user_creation.UserCreationRequest;
import common.protocol.ProtocolChannel;
import common.protocol.messages.AdminAuth;
import common.protocol.messages.AdminInsertVideoRequest;
import common.protocol.messages.AuthenticateMessage;
import common.protocol.messages.DownloadRequestMessage;
import common.protocol.messages.DownloadResponseMessage;
import common.protocol.messages.PubKeyRequest;
import common.protocol.messages.StatusMessage;
import common.protocol.user_auth.AuthenticationHandler;
import common.protocol.user_auth.User;
import common.protocol.user_auth.UserDatabase;
import merrimackutil.util.NonceCache;


public class ConnectionHandler implements Runnable {

    private ProtocolChannel channel;
    private NonceCache nonceCache;
    private boolean doDebug = false;
    private String serviceName;
    private String secret;
    private byte[] sessionKey;

    /**
     * Constructs a new connection handler for the given connection.
     * @param sock the socket to communicate over.
     * @param doDebug if tracing should be turned on or not.
     * @param serviceName the name of the service.
     * @param secret the secret.
     * @param nonceCache the nonce cache of the daemon.
     * @throws IllegalArgumentException the socket is invalid.
     * @throws IOException we can't read or write from the channel.
     */
    public ConnectionHandler(Socket sock, boolean doDebug, String serviceName, String secret, NonceCache nonceCache) throws IllegalArgumentException, IOException
    {
        this.channel = new ProtocolChannel(sock);
        this.channel.addMessageType(new common.protocol.user_creation.UserCreationRequest());
        this.channel.addMessageType(new common.protocol.messages.StatusMessage());
        this.channel.addMessageType(new common.protocol.messages.AdminInsertVideoRequest());
        this.channel.addMessageType(new common.protocol.messages.DownloadRequestMessage());
        this.channel.addMessageType(new common.protocol.messages.SearchRequestMessage());
        this.channel.addMessageType(new common.protocol.messages.SearchResponseMessage());
        this.channel.addMessageType(new common.protocol.messages.PubKeyRequest());
        this.channel.addMessageType(new AuthenticateMessage());
        this.channel.addMessageType(new AdminAuth());
       
  
      
        this.doDebug = doDebug;

        this.nonceCache = nonceCache;
        this.serviceName = serviceName;
        this.secret = secret;
    }

    /**
     * Handles the Bulitin service connection.
     */
    @Override
    public void run() {

        runCommunication();
        channel.closeChannel();
      }

      /**
       * Run the communication between the service and the client after the handshake.
       */
      private void runCommunication() {
        try {
            while (true) {
                System.out.println("[DEBUG] Waiting to receive a message...");
                
                Message msg = null;
    
                try {
                    // Try to receive the message
                    msg = channel.receiveMessage();
                    System.out.println("[DEBUG] Received message of type: " + msg.getType());
                } catch (NullPointerException e) {
                    // If a NullPointerException occurs, log it and continue waiting for the next message
                    System.err.println("[ERROR] NullPointerException encountered while receiving message.");
                    System.err.println("[DEBUG] Received message: " + msg);
                    // You can decide whether to break out of the loop or continue waiting
                    continue; // Continue waiting for the next message
                }
                System.out.println("[DEBUG] Received message: " + msg);
            if (msg.getType().equals("create-account")) {
                System.out.println("[SERVER] Received CreateMessage.");
                // Handle CreateMessage 
                handleCreateMessage(msg);
                return;
            } else if (msg.getType().equals("authenticate")) {
            boolean success = AuthenticationHandler.authenticate((AuthenticateMessage) msg);

            if (success) {
                channel.sendMessage(new StatusMessage(true, "Authentication successful."));
            } else {
                channel.sendMessage(new StatusMessage(false, "Authentication failed. Check your password or OTP."));
            }
            return;
        }
        else if (msg.getType().equals("AdminAuth")) {
            System.out.println("[SERVER] Received AdminAuth.");
            boolean success = AdminAuthenticator.authenticate((AdminAuth) msg);

            if (success) {
                channel.sendMessage(new StatusMessage(true, "Authentication successful."));
                continue; // Continue waiting for the next message
            } else {
                channel.sendMessage(new StatusMessage(false, "Authentication failed. Check your password or OTP."));
                return;
            }
            
        }else if (msg.getType().equals("PubKeyRequest")) {
            System.out.println("[SERVER] Received PubKeyRequest.");
        
            PubKeyRequest pubKeyRequest = (PubKeyRequest) msg;
            String username = pubKeyRequest.getUser();  // Use getUser() here
            System.out.println("[SERVER] Public key requested for user: " + username);
        
            String base64Key = UserDatabase.getEncodedPublicKey(username) ;  // You might want to change this to take a username
            System.out.println("[SERVER] Sending public key (Base64): " + base64Key);
        
            channel.sendMessage((Message) new StatusMessage(true, base64Key));
            System.out.println("[SERVER] Public key sent.");
        }
        else if (msg.getType().equals("AdminInsertVideoRequest")) {
            System.out.println("[SERVER] Received AdminInsertVideoRequest.");
            // Handle AdminInsertVideoRequest
            handleAdminInsertVideoRequest(msg);
            return;
        } else if (msg.getType().equals("DownloadRequest")) {
            System.out.println("[SERVER] Received DownloadRequest.");
            handleDownloadRequest((DownloadRequestMessage) msg);
            continue; // Continue waiting for the next message
        }
         else {
            System.out.println("[SERVER] Unknown or unsupported message type: " + msg.getType());
        }

    }
}catch (Exception ex) {
        ex.printStackTrace();
    }
}

            
       

    private void handleAdminInsertVideoRequest(Message msg) throws Exception {
        if (!AdminVerifier.verifyAdminFile(Configuration.getAdminFile())) {
            System.err.println("SECURITY ERROR: admin.json failed verification! Server shutting down.");
            System.exit(1);
        }

        AdminInsertVideoRequest req = (AdminInsertVideoRequest) msg;
        String username = req.getUsername();

        System.out.println("[SERVER] Video upload requested by: " + username);

        if (!Admin.isAdmin(username)) {
            System.out.println("[SERVER] User is not an admin: " + username);
            channel.sendMessage(new StatusMessage(false, "Permission denied: not an admin."));
            return;
        }

        try {
            String videoPath = req.getVideofile();
            String videoName = req.getVideoname();
            String videoCategory = req.getCategory();
            String videoAgeRating = req.getAgerating();

            System.out.println("[SERVER] Inserting video: " + videoName);

            // Encrypt and save the video
            Protector protector = new Protector(Admin.getEncryptedAESKey(), Admin.getAesIV());
            Path encryptedPath = protector.protectContent(new File(videoPath));

            // Insert into the video database
            videodatabase.insertVideo(encryptedPath, videoName, videoCategory, videoAgeRating);

            System.out.println("[SERVER] Video inserted.");
            channel.sendMessage(new StatusMessage(true, "Video inserted successfully."));

        } catch (Exception e) {
            System.err.println("[SERVER ERROR] Video insertion failed: " + e.getMessage());
            e.printStackTrace();
            channel.sendMessage(new StatusMessage(false, "Video insertion failed: " + e.getMessage()));
        }
    }

        /**
         * Handles a CreateMessage sent by the client. Creates a new user account using the
         * username, password, and public key provided in the message, and saves the
         * account information to the user database file specified in the
         * Configuration. Sends a StatusMessage back to the client with a boolean indicating
         * success or failure and a message containing the base64 encoded TOTP key if
         * successful, or an error message otherwise.
         * 
         * @param msg the CreateMessage received from the client
         */
        private void handleCreateMessage(Message msg) {
            try {
                System.out.println("[SERVER] Handling CreateMessage");
        
                UserCreationRequest createMsg = (UserCreationRequest) msg;
        
                String username = createMsg.getUsername();
                String password = createMsg.getPassword();
                String publicKey = createMsg.getPublicKey();
                String encryptedAESKey = createMsg.getEncryptedAESKey();
                String aesIV = createMsg.getAesIV();
                String userfile = Configuration.getUsersFile();
        
                System.out.println("[SERVER] Creating account for: " + username);
                System.out.println("[SERVER] AES IV: " + aesIV);
                System.out.println("[SERVER] Encrypted AES Key: " + encryptedAESKey);
                System.out.println("[SERVER] Users file: " + userfile);
        
                StatusMessage response = CreateAccount.createAccount(
                    username, password, publicKey,
                    encryptedAESKey, aesIV, userfile
                );
        
                channel.sendMessage(response);
        
            } catch (Exception e) {
                System.err.println("[SERVER] Error handling account creation:");
                e.printStackTrace();
            }
        }
      

        private void handleDownloadRequest(DownloadRequestMessage msg) {
            try {
                System.out.println("[SERVER] Handling DownloadRequest.");
                String requestedFile = msg.getFilename();
                String user = msg.getUsername();
        
                System.out.println("[SERVER] User " + user + " requested file: " + requestedFile);
        
                // 1. Locate the video
                List<Video> allVideos = videodatabase.getAllVideos();
                Video target = null;
                for (Video v : allVideos) {
                    if (v.getVideoName().equals(requestedFile)) {
                        target = v;
                        break;
                    }
                }
        
                if (target == null) {
                    channel.sendMessage(new StatusMessage(false, "Video not found."));
                    return;
                }
        
                File encFile = target.getEncryptedPath().toFile();
                if (!encFile.exists()) {
                    channel.sendMessage(new StatusMessage(false, "Encrypted file not found."));
                    return;
                }
        
                // 2. Decrypt using admin AES key and IV
                Admin.getInstance();
                Unprotector unprotector = new Unprotector(Admin.getEncryptedAESKey(), encFile, Admin.getAesIV());
                Path decryptedPath = unprotector.unprotectContent(encFile);
        
                if (!Files.exists(decryptedPath)) {
                    channel.sendMessage(new StatusMessage(false, "Failed to decrypt video."));
                    return;
                }
        
                byte[] decryptedVideo = Files.readAllBytes(decryptedPath);
        
                // 3. Get user's session AES key and IV from the user database
                byte[] sessionKey = Base64.getDecoder().decode(UserDatabase.getAesKey(user));
                byte[] iv = Base64.getDecoder().decode(UserDatabase.getAesIV(user));
        
                SecretKey aesKey = new SecretKeySpec(sessionKey, "AES");
        
                // 4. Encrypt the video with the session AES key
                byte[] reEncrypted = CryptoUtils.encrypt(decryptedVideo, aesKey, iv);
        
                // 5. Encrypt AES session key with user's public ElGamal key
                String userPubKeyB64 = UserDatabase.getEncodedPublicKey(user);
                if (userPubKeyB64 == null) {
                    channel.sendMessage(new StatusMessage(false, "No public key found for user."));
                    return;
                }
        
                byte[] pubKeyBytes = Base64.getDecoder().decode(userPubKeyB64);
                KeyFactory factory = KeyFactory.getInstance("ElGamal", "BC");
                X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
                PublicKey userPubKey = factory.generatePublic(pubKeySpec);
        
                Cipher elgCipher = Cipher.getInstance("ElGamal", "BC");
                elgCipher.init(Cipher.ENCRYPT_MODE, userPubKey);
                byte[] encryptedSessionKey = elgCipher.doFinal(sessionKey); // <== this is what was missing!
        
                // 6. Send back the encrypted video and key
                DownloadResponseMessage response = new DownloadResponseMessage(
                    Base64.getEncoder().encodeToString(reEncrypted),                    // Encrypted video
                    target.getVideoCategory(),                                         // Category
                    target.getVideoName(),                                             // Name
                    target.getVideoAgeRating(),                                        // Age rating
                    Base64.getEncoder().encodeToString(encryptedSessionKey),           // Encrypted AES key
                    Base64.getEncoder().encodeToString(iv)                             // IV
                );
        
                channel.sendMessage(response);
                System.out.println("[SERVER] Sent encrypted video to user.");
                Files.deleteIfExists(decryptedPath); // cleanup
        
            } catch (Exception e) {
                System.err.println("[SERVER ERROR] " + e.getMessage());
                e.printStackTrace();
                try {
                    channel.sendMessage(new StatusMessage(false, "Download failed: " + e.getMessage()));
                } catch (Exception ignored) {}
            }
        }
        
    
    
}
