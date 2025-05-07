package server.Admin;

import merrimackutil.json.JSONSerializable;
import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONType;
import merrimackutil.json.types.JSONObject;

import java.io.File;
import java.io.InvalidObjectException;

/**
 * Represents the root administrator for the application.
 * 
 * This class holds the sensitive data for the root user account, such as password, TOTP key,
 * public key, encrypted AES key, and initialization vector (IV). It also provides mechanisms to
 * serialize and deserialize the admin information from and to JSON format.
 * 
 */

public class Admin implements JSONSerializable {
    private String salt;
    private String pass;
    private String totpKey;
    private String user;
    private String pubkey;
    private static String encryptedAESKey;
    private static String aesIV;

    // Static admin instance
    private static Admin instance;

    public Admin() {}

    /**
     * Constructor for creating an Admin object with specified values for all fields.
     * 
     * @param salt the salt used in password hashing
     * @param pass the hashed password of the admin
     * @param totpKey the key used for TOTP (Time-based One-Time Password)
     * @param user the username of the admin
     * @param pubkey the public key used for the admin
     * @param encryptedAESKey the AES key used for encrypting sensitive data
     * @param aesIV the initialization vector (IV) used for AES encryption
     */
    public Admin(String salt, String pass, String totpKey, String user, String pubkey, String encryptedAESKey, String aesIV) {
        this.salt = salt;
        this.pass = pass;
        this.totpKey = totpKey;
        this.user = user;
        this.pubkey = pubkey;
        this.encryptedAESKey = encryptedAESKey;
        this.aesIV = aesIV;
    }

    public String getSalt() { return salt; }
    public String getPass() { return pass; }
    public String getPasswordHash() { return pass; }
    public String getTotpKey() { return totpKey; }
    public String getUser() { return user; }
    public String getPubkey() { return pubkey; }
    public static String getEncryptedAESKey() { return encryptedAESKey; }
    public static String getAesIV() { return aesIV; }

    /**
     * Deserializes the given JSON object into the fields of this Admin instance.
     *
     * @param obj the JSON object to deserialize
     * @throws InvalidObjectException if the object is not a valid JSON object or missing required fields
     */
    @Override
    public void deserialize(JSONType obj) throws InvalidObjectException {
        if (!obj.isObject()) {
            throw new InvalidObjectException("Expected a JSON object for user.");
        }
        JSONObject json = (JSONObject) obj;
        this.salt = json.getString("salt");
        this.pass = json.getString("pass");
        this.totpKey = json.getString("totp-key");
        this.user = json.getString("user");
        this.pubkey = json.getString("pubkey");
        this.encryptedAESKey = json.getString("encryptedAESKey");
        this.aesIV = json.getString("aesIV");
    }

    /**
     * Converts this Admin object into a JSON representation.
     *
     * @return the JSON representation of this Admin instance
     */
    @Override
    public JSONType toJSONType() {
        JSONObject json = new JSONObject();
        json.put("salt", salt);
        json.put("pass", pass);
        json.put("totp-key", totpKey);
        json.put("user", user);
        json.put("pubkey", pubkey);
        json.put("encryptedAESKey", encryptedAESKey);
        json.put("aesIV", aesIV);
        return json;
    }

    /**
     * Updates a specific field of the Admin object.
     *
     * @param key the key of the field to update
     * @param value the new value to set for the field
     * @throws IllegalArgumentException if an invalid key is provided
     */
    public void put(String key, String value) {
        switch (key) {
            case "salt":
                this.salt = value;
                break;
            case "pass":
                this.pass = value;
                break;
            case "totp-key":
                this.totpKey = value;
                break;
            case "user":
                this.user = value;
                break;
            case "pubkey":
                this.pubkey = value;
                break;
            case "encryptedAESKey":
                this.encryptedAESKey = value;
                break;
            case "aesIV":
                this.aesIV = value;
                break;
            default:
                throw new IllegalArgumentException("Invalid key: " + key);
        }
    }

    /**
     * Checks if the given username belongs to the root admin.
     *
     * @param username the username to check
     * @return true if the username matches the admin's username, false otherwise
     */
    public static boolean isAdmin(String username) {
        Admin admin = getInstance();
        return admin != null && admin.getUser().equals(username);
    }

    /**
     * Loads the singleton instance of the Admin class from a JSON file.
     * This method reads the admin file, deserializes its content, and creates an Admin instance if
     * the file exists and is valid.
     *
     * @return the singleton instance of the Admin class, or null if loading fails
     */
    public static Admin getInstance() {
        if (instance == null) {
            try {
                File adminFile = new File(server.Configuration.getAdminFile());
                System.out.println("[DEBUG] Admin file path: " + adminFile.getAbsolutePath());
                
                // Check if the file exists
                if (!adminFile.exists()) {
                    System.err.println("[Admin] Error: Admin file does not exist.");
                    return null;
                }

                JSONObject entry = (JSONObject) JsonIO.readObject(adminFile);
                System.out.println("[DEBUG] Loaded admin.json: " + entry.toString());

             

                // Create Admin instance
                instance = new Admin(
                    entry.getString("salt"),
                    entry.getString("pass"),
                    entry.getString("totp-key"),
                    entry.getString("user"),
                    entry.getString("pubkey"),
                    entry.getString("encryptedAESKey"),
                    entry.getString("aesIV")
                );
                System.out.println("[DEBUG] Admin instance loaded successfully.");
            } catch (Exception e) {
                System.err.println("[Admin] Error loading admin.json: " + e.getMessage());
                e.printStackTrace();
            }
        }
        return instance;
    }
}
