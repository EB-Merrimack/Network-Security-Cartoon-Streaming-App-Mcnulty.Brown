package common.protocol.messages;

import merrimackutil.json.types.*;
import common.protocol.Message;
import java.io.InvalidObjectException;

public class DownloadResponseMessage implements Message {
    private String encryptedVideo;
    private String encryptedAESKey;
    private String iv;
    private String filename;

    public DownloadResponseMessage() {}

    public DownloadResponseMessage(String filename, String encryptedVideo, String encryptedAESKey, String iv) {
        this.filename = filename;
        this.encryptedVideo = encryptedVideo;
        this.encryptedAESKey = encryptedAESKey;
        this.iv = iv;
    }


    // Getters
    public String getEncryptedVideo() {
        return encryptedVideo;
    }
    
    public String getEncryptedAESKey() {
        return encryptedAESKey;
    }
    
    public String getIv() {
        return iv;
    }


    @Override
    public String getType() {
        return "DownloadResponse";
    }

    @Override
    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();
        obj.put("type", getType());
        obj.put("encryptedVideo", encryptedVideo);
        obj.put("encryptedAESKey", encryptedAESKey);
        obj.put("iv", iv);
        return obj;
    }

    @Override
    public void deserialize(JSONType type) throws InvalidObjectException {
        if (!(type instanceof JSONObject)) throw new InvalidObjectException("Expected JSONObject.");
        JSONObject obj = (JSONObject) type;
        encryptedVideo = obj.getString("encryptedVideo");
        encryptedAESKey = obj.getString("encryptedAESKey");
        iv = obj.getString("iv");
    }

    @Override
    public Message decode(JSONObject obj) throws InvalidObjectException {
        DownloadResponseMessage msg = new DownloadResponseMessage();
        msg.deserialize(obj);
        return msg;
    }
}