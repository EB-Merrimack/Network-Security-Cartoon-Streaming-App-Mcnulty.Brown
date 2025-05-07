package common.protocol.user_auth;

import merrimackutil.json.JSONSerializable;
import merrimackutil.json.types.JSONType;
import merrimackutil.json.types.JSONObject;

import java.io.InvalidObjectException;

/**
 * Represents a user in the authentication protocol.
 * Stores cryptographic credentials and provides serialization support for JSON.
 */
public class User implements JSONSerializable {
    private String salt;
    private String pass;
    private String totpKey;
    private String user;
    private  String pubkey;
    private String encryptedAESKey;
    private String aesIV;

    /**
     * Default constructor for creating an empty User object.
     */
    public User() {}

    
    /**
     * Constructs a User object with all required fields.
     *
     * @param salt The salt used in password hashing.
     * @param pass The hashed password.
     * @param totpKey The secret key used for TOTP-based 2FA.
     * @param user The username.
     * @param pubkey The user's public key.
     * @param encryptedAESKey The user's AES key encrypted with their public key.
     * @param aesIV The IV used for AES encryption.
     */
    public User(String salt, String pass, String totpKey, String user, String pubkey, String encryptedAESKey, String aesIV) {
        this.salt = salt;
        this.pass = pass;
        this.totpKey = totpKey;
        this.user = user;
        this.pubkey = pubkey;
        this.encryptedAESKey = encryptedAESKey;
        this.aesIV = aesIV;
    }

    /**
     * @return The salt associated with the user.
     */
    public String getSalt() { return salt; }

     /**
     * @return The hashed password.
     */
    public String getPass() { return pass; }

     /**
     * @return The hashed password (alias for getPass()).
     */
    public String getPasswordHash() { return pass; }

    /**
     * @return The TOTP secret key for two-factor authentication.
     */
    public String getTotpKey() { return totpKey; }

     /**
     * @return The username.
     */
    public String getUser() { return user; }

    /**
     * @return The user's public RSA key.
     */
    public String getPubkey() { return pubkey; }

    /**
     * @return The AES key encrypted with the user's public key.
     */
    public String getEncryptedAESKey() { return encryptedAESKey; }

    /**
     * @return The initialization vector used with AES encryption.
     */
    public String getAesIV() { return aesIV; }

    /*
     * Populates the User object from a JSON object
     * 
     * @param obj  The JSON object representing the user,
     * @throws  InvaildObjectException  if the input is not a valid JSON object
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
     * Serializes the User object into a JSON object.
     *
     * @return A JSONObject representing the user.
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
}