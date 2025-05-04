package server;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import merrimackutil.json.types.*;
import merrimackutil.json.*;
import merrimackutil.json.parser.JSONParser;

public class videodatabase {
    
    private static final String DATABASE_FILE = "videos.json";

    // Method to insert a video into the "database" (a JSON file)
    public static void insertVideo(Path encryptedPath, String videoName, String videoCategory, String videoAgeRating) {
        try {
            // Load existing video list or create a new one
            List<JSONObject> videoList = loadDatabase();

            // Create a new video entry
            JSONObject newVideo = new JSONObject();
            newVideo.put("encryptedPath", encryptedPath.toString());  // <-- Save the encrypted path
            newVideo.put("videoName", videoName);
            newVideo.put("videoCategory", videoCategory);
            newVideo.put("videoAgeRating", videoAgeRating);

            // Add the new video entry
            videoList.add(newVideo);

            // Save back to file
            saveDatabase(videoList);

            System.out.println("[INFO] Video inserted successfully into the database.");

        } catch (Exception e) {
            System.out.println("[ERROR] Failed to insert video: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static List<JSONObject> loadDatabase() throws IOException {
        File dbFile = new File(DATABASE_FILE);
        List<JSONObject> videoList = new ArrayList<>();

        if (dbFile.exists()) {
            JSONObject root = (JSONObject) JSONParser.parse(dbFile);
            JSONArray videos = root.getArray("videos");
            if (videos != null) {
                for (Object entry : videos) {
                    if (entry instanceof JSONObject) {
                        videoList.add((JSONObject) entry);
                    }
                }
            }
        }
        return videoList;
    }

    private static void saveDatabase(List<JSONObject> videoList) throws IOException {
        JSONObject root = new JSONObject();
        JSONArray videos = new JSONArray();
        for (JSONObject video : videoList) {
            videos.add(video);
        }
        root.put("videos", videos);

        try (FileWriter writer = new FileWriter(DATABASE_FILE)) {
            writer.write(root.toString());
        }
    }
}
