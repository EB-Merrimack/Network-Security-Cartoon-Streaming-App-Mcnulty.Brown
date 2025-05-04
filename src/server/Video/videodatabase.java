package server.Video;
import server.Configuration;
import server.Video.Video; // ✅ use Video class

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import merrimackutil.json.types.*;
import merrimackutil.json.*;
import merrimackutil.json.parser.JSONParser;

public class videodatabase {

    private static final String DATABASE_FILE = Configuration.getVideoDatabase();

    // Insert a Video into the "database" (videos.json)
    public static void insertVideo(Path encryptedPath, String videoName, String videoCategory, String videoAgeRating) {
        try {
            List<Video> videoList = loadDatabase();

            // Create and add a new Video object
            Video newVideo = new Video(encryptedPath, videoName, videoCategory, videoAgeRating);
            videoList.add(newVideo);

            saveDatabase(videoList);

            System.out.println("[INFO] Video inserted successfully into the database.");

        } catch (Exception e) {
            System.out.println("[ERROR] Failed to insert video: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // Load the video database and return List<Video>
    private static List<Video> loadDatabase() throws IOException {
        File dbFile = new File(DATABASE_FILE);
        List<Video> videoList = new ArrayList<>();

        if (dbFile.exists()) {
            JSONObject root = JsonIO.readObject(new File(DATABASE_FILE));
            JSONArray videos = root.getArray("videos");
            if (videos != null) {
                for (Object entry : videos) {
                    if (entry instanceof JSONObject) {
                        JSONObject obj = (JSONObject) entry;

                        String encryptedPathStr = obj.getString("encryptedPath");
                        String videoName = obj.getString("videoName");
                        String videoCategory = obj.getString("videoCategory");
                        String videoAgeRating = obj.getString("videoAgeRating");

                        Video video = Video.fromJsonFields(encryptedPathStr, videoName, videoCategory, videoAgeRating);
                        videoList.add(video);
                    }
                }
            }
        }
        return videoList;
    }

    // Save a List<Video> to the database
    private static void saveDatabase(List<Video> videoList) throws IOException {
        JSONObject root = new JSONObject();
        JSONArray videos = new JSONArray();

        for (Video video : videoList) {
            JSONObject obj = new JSONObject();
            obj.put("encryptedPath", video.getEncryptedPath().toString());
            obj.put("videoName", video.getVideoName());
            obj.put("videoCategory", video.getVideoCategory());
            obj.put("videoAgeRating", video.getVideoAgeRating());
            videos.add(obj);
        }

        root.put("videos", videos);

        try (FileWriter writer = new FileWriter(DATABASE_FILE)) {
            writer.write(root.toString());
        }
    }
}
