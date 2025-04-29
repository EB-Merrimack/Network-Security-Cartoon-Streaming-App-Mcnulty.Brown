package common.protocol.messages;

import merrimackutil.json.types.*;
import common.protocol.Message;
import java.io.InvalidObjectException;

public class DownloadCompleteMessage implements Message {
    public DownloadCompleteMessage() {}

    @Override
    public void deserialize(JSONType obj) throws InvalidObjectException {
        if (!(obj instanceof JSONObject)) {
            throw new InvalidObjectException("Expected JSONObject");
        }
        // No fields inside, just type
    }

    @Override
    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();
        obj.put("type", "DownloadComplete");
        return obj;
    }

    @Override
    public String getType() {
        return "DownloadComplete";
    }

    @Override
    public Message decode(JSONObject obj) throws InvalidObjectException {
        DownloadCompleteMessage msg = new DownloadCompleteMessage();
        msg.deserialize(obj);
        return msg;
    }

    @Override
    public String toString() {
        return "[DownloadCompleteMessage]";
    }
}