
package server;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import server.Configuration;
import server.Admin.Admin;
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
import common.protocol.messages.PubKeyRequest;
import common.protocol.messages.StatusMessage;
import common.protocol.user_auth.AuthenticationHandler;
import common.protocol.user_auth.UserDatabase;
import merrimackutil.util.NonceCache;

public class ConnectionHandler implements Runnable {

private final Socket sock;
    private final ProtocolChannel channel;
    private final NonceCache nonceCache;
    private final boolean doDebug;
    private final String serviceName;
    private final String secret;

    public ConnectionHandler(Socket sock, boolean doDebug, String serviceName, String secret, NonceCache nonceCache) throws IllegalArgumentException, IOException {
        this.sock = sock;
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

    @Override
    public void run() {
        runCommunication();
        channel.closeChannel();
    }

    private void runCommunication() {
        try {
            while (true) {
                System.out.println("[DEBUG] Waiting to receive a message...");

                Message msg = channel.receiveMessage();
                if (msg == null) {
                    System.out.println("[DEBUG] Received null message, continuing.");
                    continue;
                }
                System.out.println("[DEBUG] Received message of type: " + msg.getType());

                switch (msg.getType()) {
                    case "create-account":
                        handleCreateMessage(msg);
                        return;
                    case "authenticate":
                        boolean success = AuthenticationHandler.authenticate((AuthenticateMessage) msg);
                        channel.sendMessage(new StatusMessage(success, success ? "Authentication successful." : "Authentication failed. Check your password or OTP."));
                        return;
                    case "AdminAuth":
                        boolean adminSuccess = AdminAuthenticator.authenticate((AdminAuth) msg);
                        channel.sendMessage(new StatusMessage(adminSuccess, adminSuccess ? "Authentication successful." : "Authentication failed. Check your password or OTP."));
                        if (!adminSuccess) return;
                        break;
                    case "PubKeyRequest":
                        PubKeyRequest pubKeyRequest = (PubKeyRequest) msg;
                        String username = pubKeyRequest.getUser();
                        String base64Key = UserDatabase.getEncodedPublicKey(username);
                        channel.sendMessage(new StatusMessage(true, base64Key));
                        break;
                    case "AdminInsertVideoRequest":
                        handleAdminInsertVideoRequest(msg);
                        return;
                    case "DownloadRequest":
                        System.out.println("[SERVER] Switching to raw download mode.");
                        handleRawDownload(sock);
                        return;
                    default:
                        channel.sendMessage(new StatusMessage(false, "Unsupported message type."));
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private void handleRawDownload(Socket sock) {
        try {
            DataInputStream in = new DataInputStream(sock.getInputStream());
            DataOutputStream out = new DataOutputStream(sock.getOutputStream());

            String username = in.readUTF();
            String filename = in.readUTF();
            int keyLen = in.readInt();
            byte[] privKeyBytes = new byte[keyLen];
            in.readFully(privKeyBytes);

            DownloadRequestMessage msg = new DownloadRequestMessage(filename, username, privKeyBytes);
            handleDownloadRequest(msg);
        } catch (Exception e) {
            System.err.println("[SERVER ERROR - RAW DOWNLOAD] " + e.getMessage());
            e.printStackTrace();
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
        Video target = allVideos.stream()
            .filter(v -> v.getVideoName().equals(requestedFile))
            .findFirst()
            .orElse(null);

        if (target == null) {
            channel.sendMessage(new StatusMessage(false, "Video not found."));
            return;
        }

        File encFile = target.getEncryptedPath().toFile();
        if (!encFile.exists()) {
            channel.sendMessage(new StatusMessage(false, "Encrypted file not found."));
            return;
        }

        // 2. Decrypt with admin AES key and IV
        Admin.getInstance();
        Unprotector unprotector = new Unprotector(Admin.getEncryptedAESKey(), encFile, Admin.getAesIV());
        Path decryptedPath = unprotector.unprotectContent(encFile);

        if (!Files.exists(decryptedPath)) {
            channel.sendMessage(new StatusMessage(false, "Failed to decrypt video."));
            return;
        }

        byte[] decryptedVideo = Files.readAllBytes(decryptedPath);

        // 3. Generate AES session key and IV
        SecureRandom rand = new SecureRandom();
        byte[] sessionKeyBytes = new byte[16];
        rand.nextBytes(sessionKeyBytes);
        SecretKey sessionKey = new SecretKeySpec(sessionKeyBytes, "AES");

        byte[] iv = new byte[12];
        rand.nextBytes(iv);

        // 4. Encrypt the video
        byte[] reEncrypted = CryptoUtils.encrypt(decryptedVideo, sessionKey, iv);

        // 5. Encrypt AES key with user's ElGamal public key
        String userPubKeyB64 = UserDatabase.getEncodedPublicKey(user);
        if (userPubKeyB64 == null) {
            channel.sendMessage(new StatusMessage(false, "No public key found for user."));
            return;
        }

        byte[] pubKeyBytes = Base64.getDecoder().decode(userPubKeyB64);
        KeyFactory factory = KeyFactory.getInstance("ElGamal", "BC");
        PublicKey userPubKey = factory.generatePublic(new X509EncodedKeySpec(pubKeyBytes));

        Cipher elgCipher = Cipher.getInstance("ElGamal", "BC");
        elgCipher.init(Cipher.ENCRYPT_MODE, userPubKey);
        byte[] encryptedSessionKey = elgCipher.doFinal(sessionKeyBytes);

        // === Send data directly via DataOutputStream ===
        DataOutputStream out = new DataOutputStream(channel.getOutputStream());

        out.writeUTF("DOWNLOAD_RESPONSE"); // a label so client knows what to expect
        out.writeUTF(Base64.getEncoder().encodeToString(reEncrypted));
        out.writeUTF(Base64.getEncoder().encodeToString(encryptedSessionKey));
        out.writeUTF(Base64.getEncoder().encodeToString(iv));
        out.writeUTF(target.getVideoCategory());
        out.writeUTF(target.getVideoName());
        out.writeUTF(target.getVideoAgeRating());

        out.flush();
        System.out.println("[SERVER] Sent encrypted video to user (raw format).");

        Files.deleteIfExists(decryptedPath); // cleanup
        System.out.println("[SERVER] Cleaned up temporary file.");

    } catch (Exception e) {
        System.err.println("[SERVER ERROR] " + e.getMessage());
        e.printStackTrace();
        try {
            channel.sendMessage(new StatusMessage(false, "Download failed: " + e.getMessage()));
        } catch (Exception ignored) {}
    }
}
    
}
