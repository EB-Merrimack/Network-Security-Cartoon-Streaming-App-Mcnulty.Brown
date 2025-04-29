package common.protocol.user_creation;

import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;
import merrimackutil.json.JSONSerializable;
import common.protocol.Message;

import java.io.InvalidObjectException;

public class UserCreationRequest implements Message {
    private String username;
    private String password;
    private String publicKey;
    private String encryptedAESKey;
    private String aesIV;

    public UserCreationRequest(String username, String password, String publicKey, String encryptedAESKey, String aesIV) {
        this.username = username;
        this.password = password;
        this.publicKey = publicKey;
        this.encryptedAESKey = encryptedAESKey;
        this.aesIV = aesIV;
    }

    @Override
    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();
        obj.put("type", "create-account");
        obj.put("username", username);
        obj.put("password", password);
        obj.put("pubkey", publicKey);
        obj.put("encryptedAESKey", encryptedAESKey);
        obj.put("aesIV", aesIV);
        return obj;
    }

    @Override
    public void deserialize(JSONType obj) throws InvalidObjectException {
        if (!(obj instanceof JSONObject)) {
            throw new InvalidObjectException("Expected JSONObject");
        }

        JSONObject json = (JSONObject) obj;
        this.username = json.getString("username");
        this.password = json.getString("password");
        this.publicKey = json.getString("pubkey");
        this.encryptedAESKey = json.getString("encryptedAESKey");
        this.aesIV = json.getString("aesIV");
    }

    @Override
    public String getType() {
        return "create-account";
    }

    @Override
    public Message decode(JSONObject obj) throws InvalidObjectException {
        UserCreationRequest req = new UserCreationRequest(
            obj.getString("username"),
            obj.getString("password"),
            obj.getString("pubkey"),
            obj.getString("encryptedAESKey"),
            obj.getString("aesIV")
        );
        return req;
    }
}