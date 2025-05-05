package admin_client;

import java.io.BufferedReader;
import java.io.Console;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.file.Files;
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

    // usage help
    public static void usage() {
        System.out.println("usage:");
        System.out.println("  adminclient -i -u <user> -h <host> -p <portnum> -v <filepath>");
        System.out.println("options:");
        System.out.println("  -i, --insertvideo   Insert a new video into the server.");
        System.out.println("  -u, --user          Username.");
        System.out.println("  -h, --host          Server hostname.");
        System.out.println("  -p, --port          Server port number.");
        System.out.println("  -v, --videofile     Path toVideo file to upload.");
        System.exit(1);
    }

    // parse arguments
    public static void processArgs(String[] args) throws Exception {
        if (args.length == 0) {
            usage();
        }

        OptionParser parser;
        LongOption[] opts = new LongOption[5];
        opts[0] = new LongOption("insertvideo", false, 'i');
        opts[1] = new LongOption("user", true, 'u');
        opts[2] = new LongOption("host", true, 'h');
        opts[3] = new LongOption("port", true, 'p');
        opts[4] = new LongOption("videofile", true, 'v');

        parser = new OptionParser(args);
        parser.setLongOpts(opts);
        parser.setOptString("iu:h:p:v:");

        Tuple<Character, String> currOpt;
        while (parser.getOptIdx() != args.length) {
            currOpt = parser.getLongOpt(false);

            switch (currOpt.getFirst()) {
                case 'i': insertvideo = true; break;
                case 'u': user = currOpt.getSecond(); break;
                case 'h': host = currOpt.getSecond(); break;
                case 'p': port = Integer.parseInt(currOpt.getSecond()); break;
                case 'v': videofile = currOpt.getSecond(); break;
                case '?':
                default: usage(); break;
            }
        }

        if (!insertvideo || user == null || host == null || port == 0 || videofile == null) {
            usage();
        }
    }

    // main logic
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        System.setProperty("javax.net.ssl.trustStore", "truststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "test12345");
    
        processArgs(args);

       if (!authenticateUser()) {
            System.out.println("[ERROR] Authentication failed. Exiting.");
            System.exit(1);
        }

        System.out.println("[INFO] Authentication successful!");

        // After login, upload the video
        sendVideoFile();
    }

    // authenticate admin
    private static boolean authenticateUser() throws Exception {
        Console console = System.console();
        String password;
        String otp;

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
        }

        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
        socket.startHandshake();

        channel = new ProtocolChannel(socket);
        channel.addMessageType(new StatusMessage());
        channel.addMessageType(new AdminAuth());
        channel.addMessageType(new AdminInsertVideoRequest());

        AdminAuth authMsg = new AdminAuth(user, password, otp);
        channel.sendMessage(authMsg);
        System.out.println("[INFO] Sent authentication message.");

        Message response = channel.receiveMessage();
        if (!(response instanceof StatusMessage)) {
            System.out.println("[ERROR] Unexpected response: " + response.getClass().getName());
            return false;
        }

        StatusMessage status = (StatusMessage) response;
        return status.getStatus();
    }

    // send video after authentication
   // send video after authentication
private static void sendVideoFile() throws Exception {
        channel.addMessageType(new StatusMessage());

        File file = new File(videofile);
        if (!file.exists()) {
            System.out.println("[ERROR] Video file not found: " + videofile);
            System.exit(1);
        }

        // Use BufferedReader for cleaner input handling
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

        System.out.print("Enter video name (or '1' to set it to null): ");
        String videoname = reader.readLine().trim();
        if (videoname.equals("1") || videoname.isEmpty()) {
            videoname = null;
        }

        System.out.print("Enter video category (or '1' to set it to null): ");
        String category = reader.readLine().trim();
        if (category.equals("1") || category.isEmpty()) {
            category = null;
        }

        System.out.print("Enter video age rating (or '1' to set it to null): ");
        String agerating = reader.readLine().trim();
        if (agerating.equals("1") || agerating.isEmpty()) {
            agerating = null;
        }

        // Send AdminInsertVideoRequest with the collected information
        AdminInsertVideoRequest request = new AdminInsertVideoRequest(user, videofile, videoname, category, agerating);
        channel.sendMessage(request);

        System.out.println("[INFO] Video upload request sent: " + videofile);

        // Wait for server acknowledgment
        Message resp = channel.receiveMessage();

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
}
