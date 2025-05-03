package common.protocol.messages;

import merrimackutil.json.JSONSerializable;
import merrimackutil.json.types.*;
import common.protocol.Message;

public class AdminInsertVideoRequest implements Message, JSONSerializable {
    private String user;
    private String password;
    private String videofile;

    // Constructor to initialize fields
    public AdminInsertVideoRequest(String user, String password, String videofile) {
        this.user = user;
        this.password = password;
        this.videofile = videofile;
    }

    public AdminInsertVideoRequest() {
        //TODO Auto-generated constructor stub
    }

    // Getter for the username
    public String getUser() {
        return user;
    }

    // Getter for the password
    public String getPassword() {
        return password;
    }

    // Getter for the video file
    public String getVideofile() {
        return videofile;
    }

    // Implementing getType from the Message interface
    @Override
    public String getType() {
        return "AdminInsertVideoRequest"; // You can change this string if you need a different type identifier
    }

    // Implementing decode from the Message interface
    @Override
    public Message decode(JSONObject jsonObject) {
        this.user = jsonObject.getString("user");
        this.password = jsonObject.getString("password");
        this.videofile = jsonObject.getString("videofile");
        return new AdminInsertVideoRequest(user, password, videofile);
    }

    // Implementing toJSONType from the JSONSerializable interface
    @Override
    public JSONType toJSONType() {
        JSONObject json = new JSONObject();
        json.put("type", getType());
        json.put("user", user);
        json.put("password", password);
        json.put("videofile",videofile);
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
                "user='" + user + '\'' +
                ", password='" + password + '\'' +
                ", videofile='" + videofile + '\'' +
                '}';
    }

    public String getVideoName() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getVideoName'");
    }

    public String getVideoPath() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getVideoPath'");
    }
}
