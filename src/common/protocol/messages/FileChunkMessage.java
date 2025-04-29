package common.protocol.messages;

import merrimackutil.json.types.*;
import common.protocol.Message;
import java.io.InvalidObjectException;
import java.util.Base64;

public class FileChunkMessage implements Message {
    private byte[] data;
    private boolean lastChunk;

    public FileChunkMessage() {}

    public FileChunkMessage(byte[] data, boolean lastChunk) {
        this.data = data;
        this.lastChunk = lastChunk;
    }

    public byte[] getData() {
        return data;
    }

    public boolean isLastChunk() {
        return lastChunk;
    }

    @Override
    public void deserialize(JSONType obj) throws InvalidObjectException {
        if (!(obj instanceof JSONObject)) {
            throw new InvalidObjectException("Expected JSONObject");
        }
        JSONObject json = (JSONObject) obj;
        this.data = Base64.getDecoder().decode(json.getString("data"));
        this.lastChunk = Boolean.parseBoolean(json.getString("lastChunk"));
    }

    @Override
    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();
        obj.put("type", "FileChunk");
        obj.put("data", Base64.getEncoder().encodeToString(data));
        obj.put("lastChunk", Boolean.toString(lastChunk));
        return obj;
    }

    @Override
    public String getType() {
        return "FileChunk";
    }

    @Override
    public Message decode(JSONObject obj) throws InvalidObjectException {
        FileChunkMessage msg = new FileChunkMessage();
        msg.deserialize(obj);
        return msg;
    }

    @Override
    public String toString() {
        return "[FileChunkMessage] lastChunk=" + lastChunk;
    }
}