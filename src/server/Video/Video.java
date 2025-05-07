package server.Video;

import java.io.InvalidObjectException;
import java.nio.file.Path;
import java.nio.file.Paths;

import merrimackutil.json.JSONSerializable;
import merrimackutil.json.types.JSONType;
import merrimackutil.json.types.JSONObject;

/**
 * Represents a video object containing information about the video, such as its encrypted path,
 * name, category, and age rating. This class also provides functionality for serializing and
 * deserializing the video data from and to JSON format.
 */
public class Video implements JSONSerializable {
    private Path encryptedPath;
    private String videoName;
    private String videoCategory;
    private String videoAgeRating;

    // Empty constructor needed for deserialization
    public Video() {}

    /**
     * Constructs a new Video object with the specified encrypted path, name, category, and age rating.
     * 
     * @param encryptedPath the path where the encrypted video is stored
     * @param videoName the name of the video
     * @param videoCategory the category of the video
     * @param videoAgeRating the age rating of the video
     */
    public Video(Path encryptedPath, String videoName, String videoCategory, String videoAgeRating) {
        this.encryptedPath = encryptedPath;
        this.videoName = videoName;
        this.videoCategory = videoCategory;
        this.videoAgeRating = videoAgeRating;
    }

    /**
     * Gets the path where the encrypted video is stored.
     *
     * @return the path of the encrypted video
     */
    public Path getEncryptedPath() {
        return encryptedPath;
    }

    /**
     * Retrieves the name of the video.
     *
     * @return the video name
     */
    public String getVideoName() {
        return videoName;
    }

    /**
     * Retrieves the category of the video.
     *
     * @return the category of the video
     */
    public String getVideoCategory() {
        return videoCategory;
    }

    /**
     * Retrieves the age rating of the video.
     *
     * @return the age rating of the video
     */

    public String getVideoAgeRating() {
        return videoAgeRating;
    }

    /**
     * Converts the Video object to a string for debugging purposes.
     *
     * @return a string representation of the Video
     */
    @Override
    public String toString() {
        return "Video{" +
                "encryptedPath=" + encryptedPath +
                ", videoName='" + videoName + '\'' +
                ", videoCategory='" + videoCategory + '\'' +
                ", videoAgeRating='" + videoAgeRating + '\'' +
                '}';
    }

    /**
     * Deserializes a JSON object into a Video object.
     * 
     * @param obj the JSON object containing the video data
     * @throws InvalidObjectException if the provided JSON object is not valid or does not contain the necessary fields
     */
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

    /**
     * Serializes the Video object to a JSON object.
     * 
     * @return a JSON representation of the Video
     */
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