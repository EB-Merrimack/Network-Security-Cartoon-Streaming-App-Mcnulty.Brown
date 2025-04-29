package common.protocol.messages;

import merrimackutil.json.types.*;
import common.protocol.Message;
import java.io.InvalidObjectException;
import java.util.ArrayList;
import java.util.List;

public class SearchResponseMessage implements Message {
    private List<String> files = new ArrayList<>();

    public SearchResponseMessage() {}

    public SearchResponseMessage(List<String> files) {
        this.files = files;
    }

    public List<String> getFiles() {
        return files;
    }

    @Override
    public void deserialize(JSONType obj) throws InvalidObjectException {
        if (!obj.isObject()) {
            throw new InvalidObjectException("Expected a JSON object for SearchResponseMessage.");
        }
        JSONObject json = (JSONObject) obj;
        JSONArray arr = (JSONArray) json.get("files");
        files = new ArrayList<>();
        for (int i = 0; i < arr.size(); i++) {
            files.add(arr.getString(i)); 
        }
    }

    @Override
    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();
        JSONArray arr = new JSONArray();
        for (String file : files) {
            arr.add(file); 
        }
        obj.put("type", "SearchResponse");
        obj.put("files", arr);
        return obj;
    }

    @Override
    public String getType() {
        return "SearchResponse";
    }

    @Override
    public Message decode(JSONObject obj) throws InvalidObjectException {
        SearchResponseMessage msg = new SearchResponseMessage();
        msg.deserialize(obj);
        return msg;
    }

    @Override
    public String toString() {
        return "[SearchResponseMessage] files=" + files;
    }
}