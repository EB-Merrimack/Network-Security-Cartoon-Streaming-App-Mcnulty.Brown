
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
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

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
import common.protocol.user_creation.UserCreationRequest;
import merrimackutil.cli.LongOption;
import merrimackutil.cli.OptionParser;
import merrimackutil.codec.Base32;
import merrimackutil.util.Tuple;
import server.Video.Video;
import server.Video.videodatabase;

import java.awt.Desktop;

/**
 * Client-side application for securely interacting with a video server.
 * Supports user account creation, login, secure file download, and video search functionalities
 * over SSL with support for OTP and Base64 private key-based authentication.
 */

public class Client {
    // Global variables
    private static ProtocolChannel channel = null;
    private static String user;
    private static String host;
    private static int port;
    private static String finalPath;
    private static boolean create = false;
    private static boolean login = false;
    private static String searchQuery;
    private static String downloadFilename;
    private static final Objects mapper = new Objects();
    private static final Scanner scanner = new Scanner(System.in);
    private static long lastAuthTime = 0;
    private static final long AUTH_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes



 /**
     * Prints command-line usage instructions for the client application.
     */
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

/**
     * Parses command-line arguments to configure client options.
     *
     * @param args The command-line arguments passed to the program.
     * @throws Exception if parsing fails or input is invalid.
     */
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

    /**
     * Authenticates a user with username, password, and one-time passcode (OTP).
     *
     * @return true if authentication is successful; false otherwise.
     * @throws Exception if SSL connection or communication fails.
     */
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

     /**
     * Checks if the user's session has expired, and if so, forces re-authentication.
     *
     * @throws Exception if re-authentication fails or input/output errors occur.
     */
    private static void checkAuthentication() throws Exception {
        if (System.currentTimeMillis() - lastAuthTime > AUTH_TIMEOUT_MS) {
            System.out.println("[INFO] Session expired. Re-authentication required.");
            if (!authenticateUser()) {
                System.out.println("[ERROR] Re-authentication failed. Exiting.");
                System.exit(1);
            }
        }
    }
    
    
    /**
     * Searches the server for videos based on specified metadata fields.
     *
     * @param encryptedPath  The encrypted path used for access control or filtering.
     * @param videoCategory  Category of the video (e.g., "Documentary").
     * @param videoName      Name or title of the video to search for.
     * @param videoAgeRating Age rating of the video content (e.g., "PG-13").
     * @throws Exception if SSL connection or message exchange fails.
     */
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
            List<SearchResponseMessage.VideoInfo> files = ((SearchResponseMessage) response).getFiles();
            if (files.isEmpty()) {
                System.out.println("No matching content found.");
            } else {
                System.out.println("Search results:");
                for (SearchResponseMessage.VideoInfo file : files) {
                    System.out.println(" - Name: " + file.videoName());
                    System.out.println("   Category: " + file.videoCategory());
                    System.out.println("   Age Rating: " + file.videoAgeRating());
                    System.out.println("   Encrypted Path: " + file.encryptedPath());
                    System.out.println();
                }
            }
        }


        channel.closeChannel();
    }


/**
     * Downloads a video file from the server using a Base64-encoded private key for decryption.
     * Prompts the user to enter a save path for the encrypted video.
     *
     * @param filename The name of the file to download.
     * @throws Exception if authentication fails, input is invalid, or SSL communication errors occur.
     */
    public static void download(String filename) throws Exception {
        checkAuthentication();

        System.out.println("[INFO] Requesting private key...");
        Console console = System.console();
        if (console == null) {
            throw new IllegalStateException("Console not available. Please run in a real terminal.");
        }

        String privKeyBase64 = console.readLine("Enter your Base64 private key: ");
        byte[] privKeyBytes = Base64.getDecoder().decode(privKeyBase64);

    // Prompt the user for the file path within quotes
    String inputPath = console.readLine("Enter the path to save the encrypted file (in quotes, using two backslashes per backslash)\n" +
                                    "(for instance \"C:\\\\tmp\\\\encrypted_file\" would resolve to C:\\tmp\\encrypted_file): ");

    // Remove the quotes around the input if present
    if (inputPath.startsWith("\"") && inputPath.endsWith("\"")) {
        inputPath = inputPath.substring(1, inputPath.length() - 1);
    }

    // Ensure the path uses proper backslashes
    inputPath = inputPath.replace("\\\\", "\\");

    // Ensure the path ends with .enc
    if (!inputPath.toLowerCase().endsWith(".enc")) {
        inputPath += ".enc";
    }

    System.out.println("[INFO] Encrypted file will be saved as: " + inputPath);

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
        DownloadRequestMessage downloadMsg = new DownloadRequestMessage(filename, user, privKeyBytes, inputPath);
        channel.sendMessage(downloadMsg);

        Message response = channel.receiveMessage();

        if (response instanceof DownloadResponseMessage) {
            DownloadResponseMessage drm = (DownloadResponseMessage) response;


            // Decode fields
            byte[] encryptedKey = Base64.getDecoder().decode(drm.getEncryptedAESKey());
            byte[] iv = Base64.getDecoder().decode(drm.getIv());
            String savePathmsg = inputPath; // Retrieve the saved file path

            Path encryptedFilePath = Path.of(savePathmsg);
            if (!Files.exists(encryptedFilePath)) {
                System.err.println("[ERROR] Encrypted video file not found at: " + encryptedFilePath);
                channel.closeChannel();
                return;
            }

            // === Unwrap AES key ===
            byte[] aesKeyBytes;
            try {
                java.security.spec.PKCS8EncodedKeySpec keySpec = new java.security.spec.PKCS8EncodedKeySpec(privKeyBytes);
                java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("ElGamal", "BC");
                java.security.PrivateKey privKey = keyFactory.generatePrivate(keySpec);

                Cipher elgamal = Cipher.getInstance("ElGamal", "BC");
                elgamal.init(Cipher.DECRYPT_MODE, privKey);
                aesKeyBytes = elgamal.doFinal(encryptedKey);

            } catch (Exception e) {
                System.err.println("[ERROR] Failed to unwrap AES key: " + e.getMessage());
                e.printStackTrace();
                channel.closeChannel();
                return;
            }

            // Prepare final decrypted path outside try-catch
            Path decryptedFilePath = Path.of(inputPath.replace(".enc", "_decrypted.mp4"));
            String finalPath = decryptedFilePath.toAbsolutePath().toString();

            // === Decrypt the video content ===
            try {
                byte[] encryptedVideoBytes = Files.readAllBytes(encryptedFilePath);

                SecretKey sessionKey = new SecretKeySpec(aesKeyBytes, "AES");
                byte[] decryptedVideo = CryptoUtils.decrypt(encryptedVideoBytes, sessionKey, iv);

                Files.write(decryptedFilePath, decryptedVideo);
                System.out.println("[INFO] Decrypted video saved to: " + finalPath);

                try {
                    if (Desktop.isDesktopSupported()) {
                        Desktop.getDesktop().open(decryptedFilePath.toFile());
                    } else {
                        System.err.println("[WARN] Desktop operations not supported on this platform.");
                    }
                } catch (Exception e) {
                    System.err.println("[ERROR] Failed to autoplay video: " + e.getMessage());
                }

            } catch (Exception e) {
                System.err.println("[ERROR] Failed to decrypt the video: " + e.getMessage());
                e.printStackTrace();
                channel.sendMessage(new StatusMessage(false, "Decryption failed: " + e.getMessage()));
                channel.closeChannel();
                return; // Important: Stop here if decryption fails
            }

            // === User-friendly summary ===
            System.out.println("\n=== Download Complete ===");
            System.out.println("Video Name     : " + drm.getVideoname());
            System.out.println("Category       : " + drm.getVideocatagory());
            System.out.println("Age Rating     : " + drm.getVideoagerating());
            System.out.println("Saved Location : " + finalPath);
            System.out.println("=========================\n");

        } else if (response instanceof StatusMessage) {
            System.out.println("[ERROR] " + ((StatusMessage) response).getPayload());
        }
    }


    
    /**
     * Launches the post-login interactive session panel.
     * Presents options to the user to search for videos, download videos, or exit.
     * Includes session timeout checks before each secure operation.
     * 
     * @throws Exception if an error occurs during the session or user interaction
     */    
    public static void interactiveSession() throws Exception {
        while (true) {
            System.out.println();
            System.out.println("========= VIDEO PORTAL =========");
            System.out.println("Welcome, " + user + "! What would you like to do?");
            System.out.println("[1] View all videos");
            System.out.println("[2] Search for videos");

            System.out.println("[3] Download a video");
            System.out.println("[4] Exit");
            System.out.print("Choice: ");
    
            String choice = scanner.nextLine().trim();
    
            switch (choice) {
                case "1":
                checkAuthentication(); //check if session timed out
                System.out.println("Enter search values for each field. If you don't want to search a field, type 'null' or press Enter.");
            
                // Ask for Encrypted Path
                System.out.print("Encrypted Path: ");
                String encryptedPath = scanner.nextLine().trim();
                if (encryptedPath.isEmpty() || encryptedPath.equalsIgnoreCase("null")) encryptedPath = null;
                clearConsole();
            
                // Ask for Video Category
                System.out.println("Enter search values for each field. If you don't want to search a field, type 'null' or press Enter.");
                System.out.print("Video Category: ");
                String videoCategory = scanner.nextLine().trim();
                if (videoCategory.isEmpty() || videoCategory.equalsIgnoreCase("null")) videoCategory = null;
                clearConsole();
            
                // Ask for Video Name
                System.out.println("Enter search values for each field. If you don't want to search a field, type 'null' or press Enter.");
                System.out.print("Video Name: ");
                String videoName = scanner.nextLine().trim();
                if (videoName.isEmpty() || videoName.equalsIgnoreCase("null")) videoName = null;
                clearConsole();
            
                // Ask for Video Age Rating
                System.out.println("Enter search values for each field. If you don't want to search a field, type 'null' or press Enter.");
                System.out.print("Video Age Rating: ");
                String videoAgeRating = scanner.nextLine().trim();
                if (videoAgeRating.isEmpty() || videoAgeRating.equalsIgnoreCase("null")) videoAgeRating = null;
                clearConsole();
            
                System.out.println("Searching..." + "\n" +
                                   "Encrypted Path: " + encryptedPath + "\n" +
                                   "Video Category: " + videoCategory + "\n" +
                                   "Video Name: " + videoName + "\n" +
                                   "Video Age Rating: " + videoAgeRating);
            
                // After collecting all inputs, you can now perform the search
                search(encryptedPath, videoCategory, videoName, videoAgeRating);
                break;
            
                case "3":
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
    
                case "4":
                    System.out.println("Goodbye, " + user + "!");
                    System.exit(0);
                    break;
    
                default:
                    System.out.println("[ERROR] Invalid option. Please choose 1, 2, 3 or 4.");
                    break;
            }
        }
    }
    
    /**
     * Main entry point for the secure video client application.
     * Handles TLS setup, command-line parsing, account creation, and login.
     * Initiates the interactive session upon successful authentication.
     * 
     * @param args command-line arguments passed at runtime
     * @throws Exception if there is a failure during initialization or execution
     */
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
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ElGamal", "BC");
            SecureRandom rand = SecureRandom.getInstanceStrong();  // Strong random source
            keyGen.initialize(512, rand);  // Pass it explicitly
            KeyPair kp = keyGen.generateKeyPair();

            
            String pubKeyEncoded = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
            String privKeyEncoded = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
            
            
           
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

    /**
     * Clears the console screen for improved readability during prompts.
     * Works on both Windows and Unix-like systems. If console cannot be cleared,
     * prints a fallback message.
     */
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