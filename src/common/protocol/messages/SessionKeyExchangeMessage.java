package common.protocol.messages;

import merrimackutil.json.types.*;
import java.io.InvalidObjectException;
import common.protocol.Message;

public class SessionKeyExchangeMessage implements Message {
    private String sessionKeyBase64; // The AES key, base64-encoded

    public SessionKeyExchangeMessage() {}

    public SessionKeyExchangeMessage(String sessionKeyBase64) {
        this.sessionKeyBase64 = sessionKeyBase64;
    }

    public String getSessionKeyBase64() {
        return sessionKeyBase64;
    }

    @Override
    public void deserialize(JSONType obj) throws InvalidObjectException {
        if (!(obj instanceof JSONObject)) {
            throw new InvalidObjectException("Expected JSONObject");
        }
        JSONObject json = (JSONObject) obj;
        this.sessionKeyBase64 = json.getString("sessionKey");
    }

    @Override
    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();
        obj.put("type", "SessionKeyExchange");
        obj.put("sessionKey", sessionKeyBase64);
        return obj;
    }

    @Override
    public String getType() {
        return "SessionKeyExchange";
    }

    @Override
    public Message decode(JSONObject obj) throws InvalidObjectException {
        SessionKeyExchangeMessage msg = new SessionKeyExchangeMessage();
        msg.deserialize(obj);
        return msg;
    }

    @Override
    public String toString() {
        return "[SessionKeyExchangeMessage] sessionKey=" + sessionKeyBase64;
    }
}