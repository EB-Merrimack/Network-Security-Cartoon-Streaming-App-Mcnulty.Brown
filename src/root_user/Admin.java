package root_user;

import merrimackutil.json.JSONSerializable;
import merrimackutil.json.types.JSONType;
import merrimackutil.json.types.JSONObject;

import java.io.InvalidObjectException;

public class Admin implements JSONSerializable {
    private String salt;
    private String pass;
    private String totpKey;
    private String user;
    private  String pubkey;
    private String encryptedAESKey;
    private String aesIV;

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
    public String getEncryptedAESKey() { return encryptedAESKey; }
    public String getAesIV() { return aesIV; }

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

}