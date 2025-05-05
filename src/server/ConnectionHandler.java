
package server;

import java.io.File;
import java.io.IOException;
import java.net.Socket;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import server.Configuration;
import server.Admin.Admin;
import server.Admin.AdminVerifier;
import server.Video.videodatabase;
import common.Video_Security.encryption.Protector;
import common.protocol.Message;
import common.protocol.user_creation.CreateAccount;
import common.protocol.user_creation.UserCreationRequest;
import common.protocol.ProtocolChannel;
import common.protocol.messages.AdminInsertVideoRequest;
import common.protocol.messages.AuthenticateMessage;
import common.protocol.messages.PubKeyRequest;
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
        this.channel.addMessageType(new AuthenticateMessage());
        this.channel.addMessageType(new PubKeyRequest());
  
      
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
        } else if (msg.getType().equals("PubKeyRequest")) {
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
    String username = req.getUsername(); // this MUST be added to your request object

    System.out.println("[SERVER] Video upload requested by: " + username);

    // Use the admin.json check, not UserDatabase
    if (!Admin.isAdmin(username)) {
        System.out.println("[SERVER] User is not an admin: " + username);
        channel.sendMessage(new StatusMessage(false, "Permission denied: not an admin."));
        return;
    }

    String videoPath = req.getVideofile();
    String videoName = req.getVideoname();
    String videoCategory = req.getCategory();
    String videoAgeRating = req.getAgerating();

    System.out.println("[SERVER] Inserting video: " + videoName);
    
    Protector protector = new Protector(Admin.getEncryptedAESKey(), Admin.getAesIV());
    Path encryptedPath = protector.protectContent(new File(videoPath));

    videodatabase.insertVideo(encryptedPath, videoName, videoCategory, videoAgeRating);

    System.out.println("[SERVER] Video inserted.");
    channel.sendMessage(new StatusMessage(true, "Video inserted."));
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
      
    
    
}
