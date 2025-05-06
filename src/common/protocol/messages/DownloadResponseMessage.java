package common.protocol.messages;

import merrimackutil.json.types.*;
import common.protocol.Message;
import java.io.InvalidObjectException;

public class DownloadResponseMessage implements Message {

    private String videocatagory;
    private String videoname;
    private String videoagerating;
    private String encryptedVideo;

    public DownloadResponseMessage() {}

    public DownloadResponseMessage(
        String encryptedVideo,
        String videocatagory,
        String videoname,
        String videoagerating
    ) {
        this.encryptedVideo = encryptedVideo;
        this.videocatagory = videocatagory;
        this.videoname = videoname;
        this.videoagerating = videoagerating;
    }

    
   

    public String getEncryptedVideo() {
        return encryptedVideo;
    }

    public String getVideocatagory() {
        return videocatagory;
    }

    public String getVideoname() {
        return videoname;
    }

    public String getVideoagerating() {
        return videoagerating;
    }

    @Override
    public String getType() {
        return "DownloadResponse";
    }

    @Override
    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();
        obj.put("type", getType());
        obj.put("encryptedVideo", encryptedVideo);
        obj.put("videocatagory", videocatagory);
        obj.put("videoname", videoname);
        obj.put("videoagerating", videoagerating);
        return obj;
    }

    @Override
    public void deserialize(JSONType type) throws InvalidObjectException {
        if (!(type instanceof JSONObject)) throw new InvalidObjectException("Expected JSONObject.");
        JSONObject obj = (JSONObject) type;
        encryptedVideo = obj.getString("encryptedVideo");
        videocatagory = obj.getString("videocatagory");
        videoname = obj.getString("videoname");
        videoagerating = obj.getString("videoagerating");
    }

    @Override
    public Message decode(JSONObject obj) throws InvalidObjectException {
        DownloadResponseMessage msg = new DownloadResponseMessage();
        msg.deserialize(obj);
        return msg;
    }
}
