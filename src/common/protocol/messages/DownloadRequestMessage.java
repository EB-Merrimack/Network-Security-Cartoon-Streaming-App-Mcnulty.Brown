package common.protocol.messages;

import merrimackutil.json.types.*;
import common.protocol.Message;
import java.io.InvalidObjectException;

public class DownloadRequestMessage implements Message {
    private String filename;
    private String username; // NEW FIELD

    public DownloadRequestMessage() {}

    public DownloadRequestMessage(String filename, String username) {
        this.filename = filename;
        this.username = username;
    }

    public String getFilename() {
        return filename;
    }

    public String getUsername() {
        return username;
    }

    @Override
    public void deserialize(JSONType obj) throws InvalidObjectException {
        if (!(obj instanceof JSONObject)) {
            throw new InvalidObjectException("Expected JSONObject");
        }
        JSONObject json = (JSONObject) obj;
        this.filename = json.getString("filename");
        this.username = json.getString("username"); // NEW
    }

    @Override
    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();
        obj.put("type", "DownloadRequest");
        obj.put("filename", filename);
        obj.put("username", username); // NEW
        return obj;
    }

    @Override
    public String getType() {
        return "DownloadRequest";
    }

    @Override
    public Message decode(JSONObject obj) throws InvalidObjectException {
        DownloadRequestMessage msg = new DownloadRequestMessage();
        msg.deserialize(obj);
        return msg;
    }

    @Override
    public String toString() {
        return "[DownloadRequestMessage] filename=" + filename + ", username=" + username;
    }
}