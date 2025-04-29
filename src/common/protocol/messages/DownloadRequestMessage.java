package common.protocol.messages;

import merrimackutil.json.types.*;
import common.protocol.Message;
import java.io.InvalidObjectException;

public class DownloadRequestMessage implements Message {
    private String filename;

    public DownloadRequestMessage() {}

    public DownloadRequestMessage(String filename) {
        this.filename = filename;
    }

    public String getFilename() {
        return filename;
    }

    @Override
    public void deserialize(JSONType obj) throws InvalidObjectException {
        if (!(obj instanceof JSONObject)) {
            throw new InvalidObjectException("Expected JSONObject");
        }
        JSONObject json = (JSONObject) obj;
        this.filename = json.getString("filename");
    }

    @Override
    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();
        obj.put("type", "DownloadRequest");
        obj.put("filename", filename);
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
        return "[DownloadRequestMessage] filename=" + filename;
    }
}