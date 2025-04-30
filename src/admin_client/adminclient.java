package admin_client;

import java.io.Console;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.security.Security;
import java.util.Scanner;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Objects;

import common.protocol.ProtocolChannel;
import common.protocol.messages.*;

import merrimackutil.cli.LongOption;
import merrimackutil.cli.OptionParser;
import merrimackutil.util.Tuple;

public class adminclient {
    // Global variables
    private static ProtocolChannel channel = null;
    private static String user;
    private static String host;
    private static int port;
    private static boolean insertvideo = false;
    private static String videofile;
    private static final Objects mapper = new Objects();

    // Print usage/help
    public static void usage() {
        System.out.println("usage:");
        System.out.println("  adminclient -i --insertvideo -u <user> -h <host> -p <portnum> -v <filename>");
        System.out.println("options:");
        System.out.println("  -i, --insertvideo   Insert a new video into the server.");
        System.out.println("  -u, --user          Username.");
        System.out.println("  -h, --host          Server hostname.");
        System.out.println("  -p, --port          Server port number.");
        System.out.println("  -v, --videofile     Video file to upload.");
        System.exit(1);
    }
    

  // Parse command-line arguments
public static void processArgs(String[] args) throws Exception {
    if (args.length == 0) {
        usage();
    }

    OptionParser parser;
    LongOption[] opts = new LongOption[6];
    opts[0] = new LongOption("insertvideo", false, 'i');
    opts[1] = new LongOption("user", true, 'u');
    opts[2] = new LongOption("host", true, 'h');
    opts[3] = new LongOption("port", true, 'p');
    opts[4] = new LongOption("videofile", true, 'v');

    parser = new OptionParser(args);
    parser.setLongOpts(opts);
    parser.setOptString("iu:w:h:p:v:");

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

    // Friendlier required argument check
    if (!insertvideo) {
        System.out.println("Error: missing -i / --insertvideo option.");
        usage();
    }
    if (user == null) {
        System.out.println("Error: missing -u / --user option.");
        usage();
    }
    if (host == null) {
        System.out.println("Error: missing -h / --host option.");
        usage();
    }
    if (port == 0) {
        System.out.println("Error: missing or invalid -p / --port option.");
        usage();
    }
    if (videofile == null) {
        System.out.println("Error: missing -v / --videofile option.");
        usage();
    }
}
public static void main(String[] args) throws Exception {
    // Add BouncyCastle provider
    Security.addProvider(new BouncyCastleProvider());

    // Parse command-line arguments
    processArgs(args);

    // Ask user for password (no echo)
    Console console = System.console();
    String password;
    if (console != null) {
        char[] passwordChars = console.readPassword("Enter your password: ");
        password = new String(passwordChars);
    } else {
        // fallback if System.console() is null
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter your password: ");
        password = scanner.nextLine();
    }

    // Connect to server
    SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
    SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
    channel = new ProtocolChannel(socket);

    // Create and send login + video upload request
    AdminInsertVideoRequest request = new AdminInsertVideoRequest(user, password, videofile);
    channel.sendMessage(request);

    // Done: exit immediately after sending
}




}