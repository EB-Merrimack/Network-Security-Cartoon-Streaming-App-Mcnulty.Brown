
package server;

import java.io.File;
import java.io.IOException;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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
import common.protocol.messages.DownloadResponseMessage;
import common.protocol.messages.SearchRequestMessage;
import common.protocol.messages.SearchResponseMessage;
import common.protocol.messages.StatusMessage;
import common.protocol.user_auth.AuthenticationHandler;
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
        this.channel.addMessageType(new common.protocol.messages.DownloadResponseMessage());
        this.channel.addMessageType(new common.protocol.messages.SearchRequestMessage());
        this.channel.addMessageType(new common.protocol.messages.SearchResponseMessage());
       
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
                
                Message msg = null;
    
                try {
                    // Try to receive the message
                    msg = channel.receiveMessage();
                } catch (NullPointerException e) {
                    // If a NullPointerException occurs, log it and continue waiting for the next message
                    System.err.println("[ERROR] NullPointerException encountered while receiving message.");
                    // You can decide whether to break out of the loop or continue waiting
                    continue; // Continue waiting for the next message
                }
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
            else if(msg.getType().equals("SearchRequest")) {
                
                    handleSearchRequest((SearchRequestMessage) msg);
                    return; 
                }
            else {
                System.out.println("[SERVER] Unknown or unsupported message type: " + msg.getType());
            }

        }
    }catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    /**
     * Processes a video search request.
     * Filters the available videos in the database based on optional
     * search criteria: encrypted path, category, name, and age rating.
     *
     * @param msg the {@link SearchRequestMessage} containing search criteria.
     */
         private void handleSearchRequest(SearchRequestMessage msg) {
        // 1. Load the full video database
        List<Video> allVideos = videodatabase.getAllVideos();  
        
    
        // 2. Extract search fields
        String encryptedPath = msg.getEncryptedPath();
        String videoCategory = msg.getVideoCategory();
        String videoName = msg.getVideoName();
        String videoAgeRating = msg.getVideoAgeRating();
    
        // 3. Filter matching videos
        List<SearchResponseMessage.VideoInfo> matchingFiles = new ArrayList<>();
        for (Video video : allVideos) {
            boolean matches = false; // Start assuming it doesn't match
    
          
    
            // FIRST CHECK: Encrypted Path
            if (encryptedPath == null || encryptedPath.equals("null") || encryptedPath.equals(video.getEncryptedPath())) {
                
                matches = true;
               
            } else {
                matches = false;
            }
    
            // Only continue checking other fields if first check passed
            if (matches) {
                // Video Category
                if (videoCategory == null  || videoCategory.equals("null") || videoCategory.equals(video.getVideoCategory())) {
                    matches = true;
                  
                }
                else {
                    matches = false;
                }
            }
                // Video Name
                if (matches){
                if (videoName == null || videoName.equals("null") || videoName.equals(video.getVideoName())) {
                    matches = true;
                 
                }
                else {
                    matches = false;
                }
            }
            if (matches) {
                
            
                // Video Age Rating
                if (videoAgeRating == null || videoAgeRating.equals("null") || videoAgeRating.equals(video.getVideoAgeRating())) {
                    matches = true;
                    
                }
                else {
                    matches = false;
                }
            }
    
            if (matches) {
                // All checks passed, add to result
                SearchResponseMessage.VideoInfo info = new SearchResponseMessage.VideoInfo(
                    video.getEncryptedPath(),
                    video.getVideoCategory(),
                    video.getVideoName(),
                    video.getVideoAgeRating()
                );
                matchingFiles.add(info);
              
            } 
        }
    
      
        // 4. Send the SearchResponseMessage
        SearchResponseMessage response = new SearchResponseMessage(matchingFiles);

        channel.sendMessage(response);
    }

    /**
     * Handles a request to insert a new video into the server's database.
     * Verifies the admin file, ensures the user is authorized as an admin,
     * encrypts the video content, and inserts metadata into the database.
     *
     * @param msg the {@link AdminInsertVideoRequest} containing video details.
     * @throws Exception if an error occurs during verification or encryption.
     */
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
                String savePath = msg.getSavePath();
                System.out.println("[SERVER] Save Path: " + savePath);
        
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
        
                // 3. Generate a fresh AES session key and IV
                SecureRandom rand = new SecureRandom();
                byte[] sessionKeyBytes = new byte[16]; // 128-bit AES
                rand.nextBytes(sessionKeyBytes);
                SecretKey sessionKey = new SecretKeySpec(sessionKeyBytes, "AES");
        
                byte[] iv = new byte[12]; // 96-bit IV for GCM
                rand.nextBytes(iv);
        
                // 4. Encrypt the video with the session AES key
                byte[] reEncrypted = CryptoUtils.encrypt(decryptedVideo, sessionKey, iv);
        
                // 5. Encrypt the AES key with the user's ElGamal public key
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
                byte[] encryptedSessionKey = elgCipher.doFinal(sessionKeyBytes);
        
                System.out.println("[SERVER] Encrypted session key: " + Base64.getEncoder().encodeToString(encryptedSessionKey));
        
                DownloadResponseMessage response = new DownloadResponseMessage(
                    target.getVideoCategory(),
                    target.getVideoName(),
                    target.getVideoAgeRating(),
                    Base64.getEncoder().encodeToString(encryptedSessionKey),
                    Base64.getEncoder().encodeToString(iv),
                    savePath
                );
                
        
               
               
        // Extract file name from the given savePath and change extension to .enc
        Path originalFilePath = Path.of(savePath);
        String fileNameWithoutExtension = getFileNameWithoutExtension(originalFilePath);
        
        // Create a new path with the .enc extension, keeping the same file name
        Path outputPath = originalFilePath.getParent().resolve(fileNameWithoutExtension + ".enc").toAbsolutePath();
        
        // Ensure the parent directories exist
        Files.createDirectories(outputPath.getParent());
        
        // Write the re-encrypted file to the specified output path
        Files.write(outputPath, reEncrypted);
        System.out.println("[SERVER] Saved re-encrypted video to: " + outputPath.toAbsolutePath());

       // Send response to client with the file save location
       channel.sendMessage(response);
        Files.deleteIfExists(decryptedPath); // Cleanup
        System.out.println("[SERVER] Cleaned up temporary decrypted file.");

    } catch (Exception e) {
        System.err.println("[SERVER ERROR] " + e.getMessage());
        e.printStackTrace();
        try {
            channel.sendMessage(new StatusMessage(false, "Download failed: " + e.getMessage()));
        } catch (Exception ignored) {}
    }
}
// Helper function to get the file name without extension
private String getFileNameWithoutExtension(Path path) {
    String fileName = path.getFileName().toString();
    int extensionIndex = fileName.lastIndexOf('.');
    if (extensionIndex > 0) {
        return fileName.substring(0, extensionIndex);
    } else {
        return fileName;  // No extension found, return the whole filename
    }
}

}