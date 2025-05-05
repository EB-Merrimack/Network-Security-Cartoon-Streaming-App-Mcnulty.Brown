package common.protocol.messages;

import java.io.InvalidObjectException;

import common.protocol.Message;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;

public class SearchRequestMessage implements Message {
    private String encryptedPath;
    private String videoCategory;
    private String videoName;
    private String videoAgeRating;

    public SearchRequestMessage() {}

    public SearchRequestMessage(String encryptedPath, String videoCategory, String videoName, String videoAgeRating) {
        this.encryptedPath = encryptedPath;
        this.videoCategory = videoCategory;
        this.videoName = videoName;
        this.videoAgeRating = videoAgeRating;
    }

    public String getEncryptedPath() {
        return encryptedPath;
    }

    public String getVideoCategory() {
        return videoCategory;
    }

    public String getVideoName() {
        return videoName;
    }

    public String getVideoAgeRating() {
        return videoAgeRating;
    }

    @Override
    public void deserialize(JSONType obj) throws InvalidObjectException {
        if (!(obj instanceof JSONObject)) {
            throw new InvalidObjectException("Expected JSONObject");
        }
        JSONObject json = (JSONObject) obj;
        this.encryptedPath = json.getString("encryptedPath");
        this.videoCategory = json.getString("videoCategory");
        this.videoName = json.getString("videoName");
        this.videoAgeRating = json.getString("videoAgeRating");
    }

    @Override
    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();
        obj.put("type", "SearchRequest");
        obj.put("encryptedPath", encryptedPath);
        obj.put("videoCategory", videoCategory);
        obj.put("videoName", videoName);
        obj.put("videoAgeRating", videoAgeRating);
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
        return "[SearchRequestMessage] EncryptedPath=" + encryptedPath +
               ", VideoCategory=" + videoCategory +
               ", VideoName=" + videoName +
               ", VideoAgeRating=" + videoAgeRating;
    }
}
