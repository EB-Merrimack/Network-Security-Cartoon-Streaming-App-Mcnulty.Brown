package server;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.SecretKey;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import common.CryptoUtils;
import merrimackutil.cli.LongOption;
import merrimackutil.cli.OptionParser;
import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONObject;
import merrimackutil.util.NonceCache;
import merrimackutil.util.Tuple;

// DRM logic example
public class DRMSystem {
  private static Configuration config = null;
    private static boolean doHelp = false;
    private static boolean doConfig = false;
    private static String configName = null;
    private static NonceCache nonceCache = null;
       /**
     * Prints the help menu.
     */
    public static void usage()
    {
        System.out.println("usage:");
        System.out.println("  Cartoon video Sever");
        System.out.println("  server --config <configfile>");
        System.out.println("  server --help");
        System.out.println("options:");
        System.out.println("  -c, --config\t\tSet the config file.");
        System.out.println("  -h, --help\t\tDisplay the help.");
        System.exit(1);
    }
 /**
     * Loads the configuration information from the configuration file.
     * @param configName the name of the configuration file.
     */
      public static void loadConfig(String configName)
    {
        JSONObject configObj = null;
        try
        {
            configObj = JsonIO.readObject(new File(configName));
        }
        catch (FileNotFoundException ex)
        {
            System.out.println("Configuration file not found."+configName);
            System.exit(1);
        }

        try
        {
            config = new Configuration(configObj);
            File configFile = new File(configName);
            config.setConfigDir(configFile.getParent());
        }
           catch (InvalidObjectException ex)
    {
        System.err.println("Invalid configuration file: " + configName);
        System.err.println("Reason: " + ex.getMessage());
        ex.printStackTrace();  // optional: prints full stack trace for debugging
        System.exit(1);
    }
    }
    /**
     * Process the command line arguments.
     * @param args the array of command line arguments.
     */
    public static void processArgs(String[] args)
    {
        OptionParser parser;

        LongOption[] opts = new LongOption[2];
        opts[0] = new LongOption("help", false, 'h');
        opts[1] = new LongOption("config", true, 'c');

        parser = new OptionParser(args);
        parser.setLongOpts(opts);
        parser.setOptString("hc:");

        Tuple<Character, String> currOpt;

        while (parser.getOptIdx() != args.length)
        {
            currOpt = parser.getLongOpt(false);

            switch (currOpt.getFirst())
            {
                case 'h':
                    doHelp = true;
                    break;
                case 'c':
                    doConfig = true;
                    configName = currOpt.getSecond();
                    break;
                case '?':
                    usage();
                    break;
            }
        }

        if (doConfig && doHelp)
            usage();

        if (doConfig)
            loadConfig(configName);
        else if (doHelp)
            usage();
        else
        loadConfig("./src/server/config.json");
    }
    /**
     * Main entry point of the bulletin board service.
     */
    public static void main(String[] args) throws IOException
    {
        processArgs(args);

        System.setProperty("javax.net.ssl.keyStore", config.getKeystoreFile());
        System.setProperty("javax.net.ssl.keyStorePassword", config.getKeystorePass());

        System.out.println("[DEBUG] Keystore file: " + config.getKeystoreFile());
        System.out.println("[DEBUG] File exists? " + new File(config.getKeystoreFile()).exists());

        SSLServerSocketFactory sslFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        SSLServerSocket server = (SSLServerSocket) sslFactory.createServerSocket(config.getPort());        System.out.println("Server started on port " + config.getPort());

        nonceCache = new NonceCache(32, 30);
        ExecutorService pool = Executors.newFixedThreadPool(10);

       while (true)
        {
            SSLSocket sock = (SSLSocket) server.accept();
            pool.submit(new ConnectionHandler(
                sock,
                false, "board", // service name expected in the ticket
                config.getKeystorePass(), // shared secret
                nonceCache
            ));
        }
    }

    public void protectContent(String content) throws Exception {
        SecretKey key = KeyManager.generateKey();
        byte[] encryptedContent = CryptoUtils.encrypt(content, key);
        // Store encrypted content and key securely
    }
}
