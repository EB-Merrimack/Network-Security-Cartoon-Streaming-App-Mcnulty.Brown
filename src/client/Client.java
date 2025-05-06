
package client;

import java.io.Console;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;

import java.security.Security;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Objects;

import common.CryptoUtils;
import common.protocol.Message;
import common.protocol.ProtocolChannel;
import common.protocol.messages.*;
import common.protocol.user_auth.UserDatabase;
import common.protocol.user_creation.UserCreationRequest;
import merrimackutil.cli.LongOption;
import merrimackutil.cli.OptionParser;
import merrimackutil.codec.Base32;
import merrimackutil.util.NonceCache;
import merrimackutil.util.Tuple;

public class Client {
    // Global variables
    private static ProtocolChannel channel = null;
    private static String user;
    private static String host;
    private static int port;
    private static boolean create = false;
    private static boolean login = false;
    private static String searchQuery;
    private static String downloadFilename;
    private static final Objects mapper = new Objects();

    private static final Scanner scanner = new Scanner(System.in);

    private static long lastAuthTime = 0;
private static final long AUTH_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes



    // Print usage/help
    public static void usage() {
        System.out.println("usage:");
        System.out.println("  client --create --user <user> --host <host> --port <portnum>");
        System.out.println("  client --login --user <user> --host <host> --port <portnum>");
        System.out.println("options:");
        System.out.println("  -c, --create     Create a new account.");
        System.out.println("  -u, --user       Username.");
        System.out.println("  -h, --host       Server hostname.");
        System.out.println("  -p, --port       Server port number.");
        System.out.println("  -l, --login      Login to an existing account.");
        System.exit(1);
    }

    // Parse command-line arguments
    public static void processArgs(String[] args) throws Exception {
        if (args.length == 0) {
            usage();
        }

        OptionParser parser;
        LongOption[] opts = new LongOption[7];
        opts[0] = new LongOption("create", false, 'c');
        opts[1] = new LongOption("user", true, 'u');
        opts[2] = new LongOption("host", true, 'h');
        opts[3] = new LongOption("port", true, 'p');
        opts[4] = new LongOption("search", true, 's');
        opts[5] = new LongOption("download", true, 'd');
        opts[6] = new LongOption("login", false, 'l');

        parser = new OptionParser(args);
        parser.setLongOpts(opts);
        parser.setOptString("cu:h:p:s:d:l:");

        Tuple<Character, String> currOpt;
        while (parser.getOptIdx() != args.length) {
            currOpt = parser.getLongOpt(false);

            switch (currOpt.getFirst()) {
                case 'c': create = true; break;
                case 'u': user = currOpt.getSecond(); break;
                case 'h': host = currOpt.getSecond(); break;
                case 'p': port = Integer.parseInt(currOpt.getSecond()); break;
                case 's': searchQuery = currOpt.getSecond(); break;
                case 'd': downloadFilename = currOpt.getSecond(); break;
                case 'l': login = true; break;
                case '?':
                default: usage(); break;
            }
        }
    }

    // Authenticate user (username + password + OTP)
    private static boolean authenticateUser() throws Exception {
        Console console = System.console();
        if (console == null) {
            throw new IllegalStateException("Console is not available. Please run in a real terminal.");
        }
    
        char[] passwordChars = console.readPassword("Enter password: ");
        String password = new String(passwordChars);
    
        String otp = console.readLine("Enter OTP: ");
    
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
        socket.startHandshake();
    
        channel = new ProtocolChannel(socket);
        channel.addMessageType(new StatusMessage());
        channel.addMessageType(new AuthenticateMessage());
    
        AuthenticateMessage authMsg = new AuthenticateMessage(user, password, otp);
        channel.sendMessage(authMsg);
    
        Message response = channel.receiveMessage();
        if (!(response instanceof StatusMessage)) {
            System.out.println("[ERROR] Unexpected response: " + response.getClass().getName());
            return false;
        }
    
        StatusMessage status = (StatusMessage) response;
        if (status.getStatus()) {
            lastAuthTime = System.currentTimeMillis(); // <<< SET after successful login
        }
        return status.getStatus();
    }
    private static void checkAuthentication() throws Exception {
        if (System.currentTimeMillis() - lastAuthTime > AUTH_TIMEOUT_MS) {
            System.out.println("[INFO] Session expired. Re-authentication required.");
            if (!authenticateUser()) {
                System.out.println("[ERROR] Re-authentication failed. Exiting.");
                System.exit(1);
            }
        }
    }
    
    
   // Search available videos
public static void search(String encryptedPath, String videoCategory, String videoName, String videoAgeRating) throws Exception {
    SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
    SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
    socket.startHandshake();

    ProtocolChannel channel = new ProtocolChannel(socket);
    channel.addMessageType(new SearchRequestMessage());
    channel.addMessageType(new SearchResponseMessage());
    channel.addMessageType(new StatusMessage());

    SearchRequestMessage searchMsg = new SearchRequestMessage();
    
    // You need to set the fields into searchMsg (assuming your SearchRequestMessage supports it)
    searchMsg.setEncryptedPath(encryptedPath);
    searchMsg.setVideoCategory(videoCategory);
    searchMsg.setVideoName(videoName);
    searchMsg.setVideoAgeRating(videoAgeRating);

    channel.sendMessage(searchMsg);

    Message response = channel.receiveMessage();
    if (response instanceof SearchResponseMessage) {
        List<String> files = ((SearchResponseMessage) response).getFiles();
        if (files.isEmpty()) {
            System.out.println("No matching content found.");
        } else {
            System.out.println("Search results:");
            for (String file : files) {
                System.out.println(" - " + file);
            }
        }
    } else if (response instanceof StatusMessage) {
        System.out.println("[ERROR] " + ((StatusMessage) response).getPayload());
    } else {
        System.out.println("[ERROR] Unexpected response: " + response);
    }

    channel.closeChannel();
}


    // Download file
    public static void download(String filename) throws Exception {
        checkAuthentication();
    
        System.out.println("[INFO] Requesting private key...");
        Console console = System.console();
        if (console == null) {
            throw new IllegalStateException("Console not available. Please run in a real terminal.");
        }
    
        String privKeyBase64 = console.readLine("Enter your Base64 private key: ");
        byte[] privKeyBytes = Base64.getDecoder().decode(privKeyBase64);
        System.out.println("[DEBUG] Private key length: " + privKeyBytes.length);
    
        String savePath = console.readLine("Enter the path to save the file: ");
    
    // Ensure savePath ends with .mp4
    if (!savePath.toLowerCase().endsWith(".mp4")) {
        savePath += ".mp4";
    }

    System.out.println("[INFO] File will be saved as: " + savePath);

    // === Connect to server ===
    System.out.println("[INFO] Downloading video..." + filename);
    SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
    SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
    socket.startHandshake();

    ProtocolChannel channel = new ProtocolChannel(socket);
    channel.addMessageType(new DownloadRequestMessage());
    channel.addMessageType(new DownloadResponseMessage());
    channel.addMessageType(new StatusMessage());

    // === Send Download Request with savePath ===
    System.out.println("[INFO] Sending download request...");
    DownloadRequestMessage downloadMsg = new DownloadRequestMessage(filename, user, privKeyBytes, savePath);
    channel.sendMessage(downloadMsg);
    
        Message response = channel.receiveMessage();
        System.out.println("[DEBUG] Received message type: " + (response != null ? response.getType() : "null"));
    
        if (response instanceof DownloadResponseMessage) {
    DownloadResponseMessage drm = (DownloadResponseMessage) response;
    System.out.println("[INFO] Received encrypted video information.");

    // === DEBUG Fields ===
    System.out.println("[DEBUG] Encrypted AES key (B64): " + drm.getEncryptedAESKey());
    System.out.println("[DEBUG] IV (B64): " + drm.getIv());
    System.out.println("[DEBUG] Save path: " + drm.getSavePath());

    // Decode fields
    byte[] encryptedKey = Base64.getDecoder().decode(drm.getEncryptedAESKey());
    byte[] iv = Base64.getDecoder().decode(drm.getIv());
    String savePathmsg = drm.getSavePath(); // Retrieve the saved file path

    // Load the encrypted video file from the save path
    Path encryptedFilePath = Path.of(savePathmsg);
    if (!Files.exists(encryptedFilePath)) {
        System.err.println("[ERROR] Encrypted video file not found at: " + encryptedFilePath);
        channel.closeChannel();
        return;
    }

    // === Unwrap AES key ===
    byte[] aesKeyBytes;
    try {
        // Assuming privKeyBytes is the private key to unwrap the AES key
        java.security.spec.PKCS8EncodedKeySpec keySpec = new java.security.spec.PKCS8EncodedKeySpec(privKeyBytes);
        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("ElGamal", "BC");
        java.security.PrivateKey privKey = keyFactory.generatePrivate(keySpec);

        Cipher elgamal = Cipher.getInstance("ElGamal", "BC");
        elgamal.init(Cipher.DECRYPT_MODE, privKey);
        aesKeyBytes = elgamal.doFinal(encryptedKey);

        System.out.println("[DEBUG] Unwrapped AES key (length): " + aesKeyBytes.length);
        System.out.println("[DEBUG] AES key (Base64): " + Base64.getEncoder().encodeToString(aesKeyBytes));
    } catch (Exception e) {
        System.err.println("[ERROR] Failed to unwrap AES key: " + e.getMessage());
        e.printStackTrace();
        channel.closeChannel();
        return;
    }

    // === Decrypt the video content ===
    try {
        byte[] encryptedVideoBytes = Files.readAllBytes(encryptedFilePath); // Read the encrypted video

        // Decrypt the video using the AES key and IV
        SecretKey sessionKey = new SecretKeySpec(aesKeyBytes, "AES");
        byte[] decryptedVideo = CryptoUtils.decrypt(encryptedVideoBytes, sessionKey, iv); // Use the appropriate decryption method

        // Save the decrypted video to a new file
        Path decryptedFilePath = Path.of(savePath.replace(".enc", "_decrypted.mp4")); // Adjust as needed (e.g., .enc -> .mp4)
        Files.write(decryptedFilePath, decryptedVideo);
        System.out.println("[INFO] Decrypted video saved to: " + decryptedFilePath.toAbsolutePath());

        // Send a status message back to the client
        channel.sendMessage(new StatusMessage(true, "Decryption successful. Video saved at: " + decryptedFilePath.toAbsolutePath()));
    } catch (Exception e) {
        System.err.println("[ERROR] Failed to decrypt the video: " + e.getMessage());
        e.printStackTrace();
        channel.sendMessage(new StatusMessage(false, "Decryption failed: " + e.getMessage()));
    }

    
            // === User-friendly summary ===
            System.out.println("\n=== Download Complete ===");
            System.out.println("Video Name     : " + drm.getVideoname());
            System.out.println("Category       : " + drm.getVideocatagory());
            System.out.println("Age Rating     : " + drm.getVideoagerating());
            System.out.println("Saved Location : " + savePath);
            System.out.println("=========================\n");
    
        } else if (response instanceof StatusMessage) {
            System.out.println("[ERROR] " + ((StatusMessage) response).getPayload());
        } else {
            System.out.println("[ERROR] Unexpected response type: " + response.getClass().getName());
        }
    
        channel.closeChannel();
    }

    
    // Create post login panel
    public static void interactiveSession() throws Exception {
        while (true) {
            System.out.println();
            System.out.println("Welcome, " + user + "! What would you like to do?");
            System.out.println("[1] Search for videos");
            System.out.println("[2] Download a video");
            System.out.println("[3] Exit");
            System.out.print("Choice: ");
    
            String choice = scanner.nextLine().trim();
    
            switch (choice) {
                case "1":
                checkAuthentication(); // <<< check if session timed out
                System.out.println("Enter search values for each field. If you don't want to search a field, type 'null' or press Enter.");
                
                // Ask for Encrypted Path
                clearConsole();
                System.out.print("Encrypted Path: ");
                String encryptedPath = scanner.nextLine().trim();
                if (encryptedPath.isEmpty()) encryptedPath = "null";
                
                // Ask for Video Category
                clearConsole();
                System.out.print("Video Category: ");
                String videoCategory = scanner.nextLine().trim();
                if (videoCategory.isEmpty()) videoCategory = "null";
                
                // Ask for Video Name
                clearConsole();
                System.out.print("Video Name: ");
                String videoName = scanner.nextLine().trim();
                if (videoName.isEmpty()) videoName = "null";
                
                // Ask for Video Age Rating
                clearConsole();
                System.out.print("Video Age Rating: ");
                String videoAgeRating = scanner.nextLine().trim();
                if (videoAgeRating.isEmpty()) videoAgeRating = "null";
                
                // After collecting all inputs, you can now perform the search
                search(encryptedPath, videoCategory, videoName, videoAgeRating);
                
                    break;
                case "2":
                    checkAuthentication(); // <<< add this
                    Scanner downloadscanner=new Scanner(System.in);
                    System.out.print("Enter filename to download: ");
                    String searchFilename = downloadscanner.nextLine().trim();
                    if (!searchFilename.isEmpty()) {
                        download(searchFilename);
                    } else {
                        System.out.println("[WARN] Filename cannot be empty.");
                    }
                
                    break;
    
                case "3":
                    System.out.println("Goodbye, " + user + "!");
                    System.exit(0);
                    break;
    
                default:
                    System.out.println("[ERROR] Invalid option. Please choose 1, 2, or 3.");
                    break;
            }
        }
    }
    
    // Main entry point
    public static void main(String[] args) throws Exception {
        // Setup TLS and Bouncy Castle
        Security.addProvider(new BouncyCastleProvider());
        System.setProperty("javax.net.ssl.trustStore", "truststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "test12345");
    
        // Parse command line arguments
        processArgs(args);
    
        if (create) {
            // --- Account Creation Flow ---
            Console console = System.console();
            if (console == null) {
                throw new IllegalStateException("Console not available. Please run in a real terminal.");
            }
    
            System.out.print("Enter a password: ");
            String password = new String(console.readPassword());
    
            // 1. Generate ElGamal keypair
            System.out.println("[DEBUG] Generating ElGamal key pair...");
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ElGamal", "BC");
            SecureRandom rand = SecureRandom.getInstanceStrong();  // Strong random source
            keyGen.initialize(512, rand);  // Pass it explicitly
            KeyPair kp = keyGen.generateKeyPair();

            
            System.out.println("[DEBUG] Encoding public key...");
            String pubKeyEncoded = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
            String privKeyEncoded = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
            
            System.out.println("[DEBUG] Public Key (Base64):\n" + pubKeyEncoded);
            
           
            // 2. Generate AES key
            KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
            aesKeyGen.init(128);
            SecretKey aesKey = aesKeyGen.generateKey();
    
            // 3. Generate AES IV
            byte[] rawIV = new byte[12];
            rand.nextBytes(rawIV);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, rawIV); // 128-bit auth tag
    
            // 4. Encrypt AES key with public key
            Cipher elgCipher = Cipher.getInstance("ElGamal", "BC");
            elgCipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
            byte[] encryptedAESKey = elgCipher.doFinal(aesKey.getEncoded());
    
            // 5. Base64 encode all values
            String encryptedAESKeyB64 = Base64.getEncoder().encodeToString(encryptedAESKey);
            String ivEncoded = Base64.getEncoder().encodeToString(rawIV);
    
            // 6. Connect to server and send request
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
            socket.startHandshake();
    
            channel = new ProtocolChannel(socket);
            channel.addMessageType(new StatusMessage());
            channel.addMessageType(new UserCreationRequest("", "", "", "", "")); // dummy for decoding
    
            UserCreationRequest req = new UserCreationRequest(user, password, pubKeyEncoded, encryptedAESKeyB64, ivEncoded);
            channel.sendMessage(req);
    
            Message response = channel.receiveMessage();
            if (response == null) {
                System.err.println("[CLIENT ERROR] No response received (null). Check message type registration.");
            }
            if (response instanceof StatusMessage) {
                StatusMessage status = (StatusMessage) response;
    
                if (status.getStatus()) {
                    System.out.println("Account created successfully.");
                    System.out.println("Save your Private Key:\n" + privKeyEncoded);
                    String totpKey = status.getPayload();
                byte[] totpBytes = Base64.getDecoder().decode(totpKey);
                String base32Totp = Base32.encodeToString(totpBytes, true); // no padding
                System.out.println("Base 32 Key:\n" + base32Totp);
                    System.out.println("[INFO] Please log in to activate your account...");
    
                    if (!authenticateUser()) {
                        System.out.println("[ERROR] Authentication failed.");
                        System.exit(1);
                    } else {
                        System.out.println("[INFO] Account activated. You are now logged in.");
                        interactiveSession();
                    }
                } else {
                    System.out.println("Failed to create account: " + status.getPayload());
                }
            } else {
                System.out.println("[ERROR] Unexpected response from server.");
            }
    
            channel.closeChannel();
            } else {
                if(login) {
                    if (!authenticateUser()) {
                        System.out.println("[ERROR] Authentication failed.");
                        System.exit(1);
                    } else {
            
                    System.out.println("[INFO] Login successful.");
                    interactiveSession();
                }
            }
        }
    }
    public static void clearConsole() {
        try {
            if (System.getProperty("os.name").contains("Windows")) {
                new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
            } else {
                System.out.print("\033[H\033[2J");
                System.out.flush();
            }
        } catch (Exception e) {
            System.out.println("Could not clear console.");
        }
    }
    
}