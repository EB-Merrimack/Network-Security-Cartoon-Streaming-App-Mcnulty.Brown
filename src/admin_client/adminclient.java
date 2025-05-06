/* 
 * Copyright (C) 2025  Emily J Brown And Erin Mcnulty
 *
 * This program is a command-line utility designed for administrative tasks on a server. 
 * It allows administrators to authenticate and upload videos to the server via secure SSL connections. 
 * The program supports several command-line options for specifying the user, server host, port number, 
 * and the video file to upload. Additionally, it provides functionality for inserting videos into the server
 *  by specifying the video details. To use the program, you must pass the appropriate flags to authenticate the user 
 * and provide the video file you wish to upload.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation, either version 3 of the License, or 
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package admin_client;

import java.io.BufferedReader;
import java.io.Console;
import java.io.File;
import java.io.InputStreamReader;
import java.util.Scanner;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import common.protocol.Message;
import common.protocol.ProtocolChannel;
import common.protocol.messages.*;

import merrimackutil.cli.LongOption;
import merrimackutil.cli.OptionParser;
import merrimackutil.util.Tuple;

public class adminclient {
    private static ProtocolChannel channel = null;
    private static String user;
    private static String host;
    private static int port;
    private static boolean insertvideo = false;
    private static String videofile;

    /**
     * Prints the usage/help information for the admin client.
     * This method provides instructions on how to use the command-line arguments.
     * It terminates the program after displaying the information.
     */
    public static void usage() {
        // Display the usage syntax for the admin client
        System.out.println("usage:");
        System.out.println("  adminclient -i -u <user> -h <host> -p <portnum> -v <filepath>");
        
        // Display the available command-line options and their descriptions
        System.out.println("options:");
        System.out.println("  -i, --insertvideo   Insert a new video into the server.");
        System.out.println("  -u, --user          Username.");
        System.out.println("  -h, --host          Server hostname.");
        System.out.println("  -p, --port          Server port number.");
        System.out.println("  -v, --videofile     Path to video file to upload.");
        
        // Exit the program after displaying the usage information
        System.exit(1);
    }

    /**
     * Parses the command-line arguments for the admin client.
     * 
     * @param args the array of command-line arguments
     * @throws Exception if there is an error during parsing
     */
    public static void processArgs(String[] args) throws Exception {
        // If no arguments are provided, show usage information
        if (args.length == 0) {
            usage();
        }

        OptionParser parser;
        LongOption[] opts = new LongOption[5];
        opts[0] = new LongOption("insertvideo", false, 'i');  // Option to insert a new video
        opts[1] = new LongOption("user", true, 'u');         // Username option
        opts[2] = new LongOption("host", true, 'h');         // Hostname option
        opts[3] = new LongOption("port", true, 'p');         // Port number option
        opts[4] = new LongOption("videofile", true, 'v');    // Video file path option

        // Initialize the option parser with the provided arguments
        parser = new OptionParser(args);
        parser.setLongOpts(opts);
        parser.setOptString("iu:h:p:v:");

        Tuple<Character, String> currOpt;
        // Iterate through each argument and process it according to its type
        while (parser.getOptIdx() != args.length) {
            currOpt = parser.getLongOpt(false);

            switch (currOpt.getFirst()) {
                case 'i': 
                    insertvideo = true; 
                    break;
                case 'u': 
                    user = currOpt.getSecond(); 
                    break;
                case 'h': 
                    host = currOpt.getSecond(); 
                    break;
                case 'p': 
                    port = Integer.parseInt(currOpt.getSecond()); 
                    break;
                case 'v': 
                    videofile = currOpt.getSecond(); 
                    break;
                case '?':
                default: 
                    usage(); 
                    break;
            }
        }

        // Validate that all required arguments are provided
        if (!insertvideo || user == null || host == null || port == 0 || videofile == null) {
            usage();
        }
    }

    /**
     * Main logic entry point for the admin client.
     *
     * @param args the command-line arguments
     * @throws Exception if an error occurs during execution
     */
    public static void main(String[] args) throws Exception {
        // Add Bouncy Castle as a Security Provider
        Security.addProvider(new BouncyCastleProvider());

        // Load SSL trust store settings
        System.setProperty("javax.net.ssl.trustStore", "truststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "test12345");

        // Parse the command-line arguments
        processArgs(args);

        // Authenticate the user before proceeding
        if (!authenticateUser()) {
            System.out.println("[ERROR] Authentication failed. Exiting.");
            System.exit(1);
        }

        System.out.println("[INFO] Authentication successful!");

        // After successful login, proceed to upload the video
        sendVideoFile();
    }

    /**
     * Authenticate the admin user.
     *
     * @return true if the authentication is successful, false otherwise
     * @throws Exception if an error occurs during authentication
     */
    private static boolean authenticateUser() throws Exception {
        Console console = System.console();
        String password;
        String otp;

        // Read the password and OTP from the user
        if (console != null) {
            char[] passwordChars = console.readPassword("Enter password: ");
            password = new String(passwordChars);
            otp = console.readLine("Enter OTP: ");
        } else {
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter password: ");
            password = scanner.nextLine();
            System.out.print("Enter OTP: ");
            otp = scanner.nextLine();
            scanner.close();
        }

        // Connect to the server
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
        socket.startHandshake();

        // Create a ProtocolChannel to send authenticated messages
        channel = new ProtocolChannel(socket);
        channel.addMessageType(new StatusMessage());
        channel.addMessageType(new AdminAuth());
        channel.addMessageType(new AdminInsertVideoRequest());

        // Send the authentication message
        AdminAuth authMsg = new AdminAuth(user, password, otp);
        channel.sendMessage(authMsg);
        System.out.println("[INFO] Sent authentication message.");

        // Receive the response from the server
        Message response = channel.receiveMessage();
        if (!(response instanceof StatusMessage)) {
            System.out.println("[ERROR] Unexpected response: " + response.getClass().getName());
            return false;
        }

        // Check the status of the response
        StatusMessage status = (StatusMessage) response;
        return status.getStatus();
    }

    /**
     * Sends a video file after authentication.
     * 
     * @throws Exception if an error occurs while sending the video file
     */
    private static void sendVideoFile() throws Exception {

        File file = new File(videofile);
        if (!file.exists()) {
            System.out.println("[ERROR] Video file not found: " + videofile);
            System.exit(1);
        }

        // Use BufferedReader for cleaner input handling
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

        // Collect video information from the user
        System.out.print("Enter video name (or '1' to set it to null): ");
        String videoname = reader.readLine().trim();
        if (videoname.equals("1") || videoname.isEmpty()) {
            videoname = null;
        }
        clearConsole();

        System.out.print("Enter video category (or '1' to set it to null): ");
        String category = reader.readLine().trim();
        if (category.equals("1") || category.isEmpty()) {
            category = null;
        }
        clearConsole();

        System.out.print("Enter video age rating (or '1' to set it to null): ");
        String agerating = reader.readLine().trim();
        if (agerating.equals("1") || agerating.isEmpty()) {
            agerating = null;
        }
        clearConsole();

        // Send AdminInsertVideoRequest with the collected information
        AdminInsertVideoRequest request = new AdminInsertVideoRequest(user, videofile, videoname, category, agerating);
        channel.sendMessage(request);

        System.out.println("[INFO] Video upload request sent: " + videofile);

        // Wait for server acknowledgment
        Message resp = channel.receiveMessage();
        System.out.println("[DEBUG] Received response: " + (resp != null ? resp.getType() : "null"));

        // Check the response
        if (resp instanceof StatusMessage) {
            StatusMessage statusMessage = (StatusMessage) resp;
            if (statusMessage.getStatus()) {
                System.out.println("[INFO] Video upload successful.");
            } else {
                System.out.println("[ERROR] Video upload failed.");
            }
        } else {
            System.out.println("[ERROR] Unexpected response type: " + resp.getClass().getName());
        }
    }

    /**
     * Clear the console screen. Works on Unix/Linux/macOS and Windows.
     * The method uses the ANSI escape sequences to clear the screen.
     * On Windows, it uses the cls command to clear the screen.
     * If the clear command fails, the method prints a warning message.
     */
    private static void clearConsole() {
        try {
            // Works on Unix/Linux/macOS
            if (System.getProperty("os.name").contains("Windows")) {
                new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
            } else {
                // ANSI escape sequences to clear the screen
                System.out.print("\033[H\033[2J");
                System.out.flush();
            }
        } catch (Exception e) {
            System.out.println("[Warning] Could not clear console.");
        }
    }
}