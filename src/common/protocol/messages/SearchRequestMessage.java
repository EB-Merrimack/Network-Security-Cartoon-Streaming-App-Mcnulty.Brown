package common.protocol.messages;

import merrimackutil.json.types.*;
import common.protocol.Message;
import java.io.InvalidObjectException;

public class SearchRequestMessage implements Message {
    private String query;

    public SearchRequestMessage() {}

    public SearchRequestMessage(String query) {
        this.query = query;
    }

    public String getQuery() {
        return query;
    }

    @Override
    public void deserialize(JSONType obj) throws InvalidObjectException {
        if (!(obj instanceof JSONObject)) {
            throw new InvalidObjectException("Expected JSONObject");
        }
        JSONObject json = (JSONObject) obj;
        this.query = json.getString("query");
    }

    @Override
    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();
        obj.put("type", "SearchRequest");
        obj.put("query", query);
        return obj;
    }

    @Override
    public String getType() {
        return "SearchRequest";
    }

    @Override
    public Message decode(JSONObject obj) throws InvalidObjectException {
        SearchRequestMessage msg = new SearchRequestMessage();
        msg.deserialize(obj);
        return msg;
    }

    @Override
    public String toString() {
        return "[SearchRequestMessage] query=" + query;
    }
}