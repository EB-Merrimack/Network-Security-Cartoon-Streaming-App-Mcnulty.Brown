package common.protocol.messages;

import merrimackutil.json.JSONSerializable;
import merrimackutil.json.types.*;
import common.protocol.Message;

public class AdminInsertVideoRequest implements Message, JSONSerializable {
    private String user;
    private String videofile;
    private String videoname;
    private String category;
    private String agerating;

    // Constructor to initialize fields
    public AdminInsertVideoRequest(String user, String videofile, String videoname, String category, String agerating) {
        this.user = user;
        this.videofile = videofile;
        this.videoname = videoname;
        this.category = category;
        this.agerating = agerating;
    }

    public AdminInsertVideoRequest() {
        // Default constructor for deserialization
    }

    // Getter for the video file
    public String getVideofile() {
        return videofile;
    }

    // Getter for the video name (title)
    public String getVideoname() {
        return videoname;
    }

    // Getter for the video category
    public String getCategory() {
        return category;
    }

    // Getter for the video age rating
    public String getAgerating() {
        return agerating;
    }

    public String getUsername() {
        return user;
    }

    // Implementing getType from the Message interface
    @Override
    public String getType() {
        return "AdminInsertVideoRequest"; // Type identifier
    }

    // Implementing decode from the Message interface
    @Override
    public Message decode(JSONObject jsonObject) {
        this.user = jsonObject.getString("user");
        this.videofile = jsonObject.getString("videofile");
        this.videoname = jsonObject.getString("videoname");
        this.category = jsonObject.getString("category");
        this.agerating = jsonObject.getString("agerating");
        return new AdminInsertVideoRequest(user, videofile, videoname, category, agerating);
    }

    // Implementing toJSONType from the JSONSerializable interface
    @Override
    public JSONType toJSONType() {
        JSONObject json = new JSONObject();
        json.put("type", getType());
        json.put("user", user);
        json.put("videofile", videofile);
        json.put("videoname", videoname);
        json.put("category", category);
        json.put("agerating", agerating);
        return json;
    }

    // Implementing deserialize from the JSONSerializable interface
    @Override
    public void deserialize(JSONType jsonType) {
        if (jsonType instanceof JSONObject) {
            JSONObject jsonObject = (JSONObject) jsonType;
            this.decode(jsonObject);  // Decode the data into this object's fields
        }
    }

    // Optionally, you can add a method to convert the object to a string for debugging
    @Override
    public String toString() {
        return "AdminInsertVideoRequest{" +
                "videofile='" + videofile + '\'' +
                ", videoname='" + videoname + '\'' +
                ", category='" + category + '\'' +
                ", agerating='" + agerating + '\'' +
                '}';
    }
}
