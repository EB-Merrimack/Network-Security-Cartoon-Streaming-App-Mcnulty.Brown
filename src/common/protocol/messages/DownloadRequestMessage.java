package common.protocol.messages;

import merrimackutil.json.types.*;
import common.protocol.Message;
import java.io.InvalidObjectException;
import java.util.Base64;

public class DownloadRequestMessage implements Message {
    private String filename;
    private String username; 
    private byte[] privKeyBytes;
    private String savePath; // <-- Added field

    public DownloadRequestMessage() {}

    public DownloadRequestMessage(String filename, String username, byte[] privKeyBytes, String savePath) {
        this.filename = filename;
        this.username = username;
        this.privKeyBytes = privKeyBytes;
        this.savePath = savePath; // <-- Store savePath
    }

    public String getFilename() {
        return filename;
    }

    public String getUsername() {
        return username;
    }

    public byte[] getPrivKeyBytes() {
        System.out.println("[INFO] DownloadRequestMessage.getPrivKeyBytes(): " + java.util.Arrays.toString(privKeyBytes));
        return privKeyBytes;
    }

    public String getSavePath() { // <-- Getter
        return savePath;
    }

    @Override
    public void deserialize(JSONType obj) throws InvalidObjectException {
        if (!(obj instanceof JSONObject)) {
            throw new InvalidObjectException("Expected JSONObject");
        }
        JSONObject json = (JSONObject) obj;
        this.filename = json.getString("filename");
        this.username = json.getString("username");
        this.privKeyBytes = Base64.getDecoder().decode(json.getString("privKeyBytes"));
        this.savePath = json.getString("savePath"); // <-- Deserialize savePath
    }

    @Override
    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();
        obj.put("type", "DownloadRequest");
        obj.put("filename", filename);
        obj.put("username", username);
        obj.put("privKeyBytes", Base64.getEncoder().encodeToString(privKeyBytes));
        obj.put("savePath", savePath); // <-- Serialize savePath
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
        return "[DownloadRequestMessage] filename=" + filename +
               ", username=" + username +
               ", privKeyBytes=" + java.util.Arrays.toString(privKeyBytes) +
               ", savePath=" + savePath; // <-- Print savePath too
    }
}
