package server.Admin;

import merrimackutil.json.JSONSerializable;
import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONType;
import merrimackutil.json.types.JSONArray;
import merrimackutil.json.types.JSONObject;

import java.io.File;
import java.io.InvalidObjectException;
import java.io.IOException;

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

    // Update a field
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

  

    // Static method to check if user is admin
    public static boolean isAdmin(String username) {
        Admin admin = getInstance();
        return admin != null && admin.getUser().equals(username);
    }
// Static method to load the Admin singleton
public static Admin getInstance() {
    if (instance == null) {
        try {
            File adminFile = new File(server.Configuration.getAdminFile());
            JSONObject entry = (JSONObject) JsonIO.readObject(adminFile);

            instance = new Admin(
                entry.getString("salt"),
                entry.getString("pass"),
                entry.getString("totp-key"),
                entry.getString("user"),
                entry.getString("pubkey"),
                entry.getString("encryptedAESKey"),
                entry.getString("aesIV")
            );
        } catch (Exception e) {
            System.err.println("[Admin] Error loading admin.json: " + e.getMessage());
        }
    }
    return instance;
}
}
