package server.Video;

import java.io.InvalidObjectException;
import java.nio.file.Path;
import java.nio.file.Paths;

import merrimackutil.json.JSONSerializable;
import merrimackutil.json.types.JSONType;
import merrimackutil.json.types.JSONObject;


public class Video implements JSONSerializable {
    private Path encryptedPath;
    private String videoName;
    private String videoCategory;
    private String videoAgeRating;

    // Empty constructor needed for deserialization
    public Video() {}

    public Video(Path encryptedPath, String videoName, String videoCategory, String videoAgeRating) {
        this.encryptedPath = encryptedPath;
        this.videoName = videoName;
        this.videoCategory = videoCategory;
        this.videoAgeRating = videoAgeRating;
    }

    public Path getEncryptedPath() {
        return encryptedPath;
    }

    public String getVideoName() {
        return videoName;
    }

    public String getVideoCategory() {
        return videoCategory;
    }

    public String getVideoAgeRating() {
        return videoAgeRating;
    }

    @Override
    public String toString() {
        return "Video{" +
                "encryptedPath=" + encryptedPath +
                ", videoName='" + videoName + '\'' +
                ", videoCategory='" + videoCategory + '\'' +
                ", videoAgeRating='" + videoAgeRating + '\'' +
                '}';
    }

    // Deserialize from JSON object
    @Override
    public void deserialize(JSONType obj) throws InvalidObjectException {
        if (!(obj instanceof JSONObject)) {
            throw new InvalidObjectException("Expected a JSONObject for Video.");
        }
        JSONObject json = (JSONObject) obj;

        this.encryptedPath = Paths.get(json.getString("encryptedPath"));
        this.videoName = json.getString("videoName");
        this.videoCategory = json.getString("videoCategory");
        this.videoAgeRating = json.getString("videoAgeRating");
    }

    // Serialize to JSON object
    @Override
    public JSONType toJSONType() {
        JSONObject json = new JSONObject();
        json.put("encryptedPath", encryptedPath.toString().replace("\\", "/"));
        json.put("videoName", videoName);
        json.put("videoCategory", videoCategory);
        json.put("videoAgeRating", videoAgeRating);
        return json;
    }
}