package common.protocol.messages;

import merrimackutil.json.types.*;
import common.protocol.Message;
import java.io.InvalidObjectException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class SearchResponseMessage implements Message {
    private List<VideoInfo> files = new ArrayList<>();

    public SearchResponseMessage() {}

    public SearchResponseMessage(List<VideoInfo> files) {
        this.files = files;
    }

    public List<VideoInfo> getFiles() {
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
            JSONObject fileObj = (JSONObject) arr.get(i);
            VideoInfo video = new VideoInfo(
                fileObj.getString("encryptedPath"),
                fileObj.getString("videoCategory"),
                fileObj.getString("videoName"),
                fileObj.getString("videoAgeRating")
            );
            files.add(video);
        }
    }

    @Override
    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();
        JSONArray arr = new JSONArray();
        for (VideoInfo file : files) {
            JSONObject fileObj = new JSONObject();
            fileObj.put("encryptedPath", file.encryptedPath());
            fileObj.put("videoCategory", file.videoCategory());
            fileObj.put("videoName", file.videoName());
            fileObj.put("videoAgeRating", file.videoAgeRating());
            arr.add(fileObj);
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

    public static record VideoInfo(String encryptedPath, String videoCategory, String videoName, String videoAgeRating) {
        public VideoInfo(Path encryptedPath, String videoCategory, String videoName, String videoAgeRating) {
            this(encryptedPath.toString(), videoCategory, videoName, videoAgeRating);
        }
    }
}
