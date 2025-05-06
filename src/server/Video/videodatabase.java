package server.Video;

import server.Configuration;
import merrimackutil.json.*;
import merrimackutil.json.types.*;

import java.io.File;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class videodatabase {

    private static final String DATABASE_FILE = Configuration.getVideoDatabase();

    // Wrapper class for saving to JSON
    private static class VideoDBWrapper implements JSONSerializable {
        private final List<Video> videoList;

        public VideoDBWrapper(List<Video> videoList) {
            this.videoList = videoList;
        }

        @Override
        public JSONType toJSONType() {
            JSONArray videos = new JSONArray();
            for (Video v : videoList) {
                videos.add(v.toJSONType());
            }
            JSONObject root = new JSONObject();
            root.put("videos", videos);
            return root;
        }

        @Override
        public void deserialize(JSONType obj) {
            // unused
        }
    }

    // Insert a new video into the database
    public static void insertVideo(Path encryptedPath, String videoName, String videoCategory, String videoAgeRating) {
        try {
            List<Video> videoList = loadDatabase();

            Video newVideo = new Video(encryptedPath, videoName, videoCategory, videoAgeRating);
            videoList.add(newVideo);

            saveDatabase(videoList);

            System.out.println("[INFO] Video inserted successfully into the database.");
        } catch (Exception e) {
            System.out.println("[ERROR] Failed to insert video: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // Load video database into a list
    private static List<Video> loadDatabase() throws IOException {
        List<Video> videoList = new ArrayList<>();
        File dbFile = new File(DATABASE_FILE);

        if (!dbFile.exists()) return videoList;

        JSONObject root = JsonIO.readObject(dbFile);
        JSONArray videos = root.getArray("videos");

        for (int i = 0; i < videos.size(); i++) {
            JSONType entry = (JSONType) videos.get(i);
            Video v = new Video();
            try {
                v.deserialize(entry);
                videoList.add(v);
            } catch (InvalidObjectException e) {
                System.err.println("[ERROR] Skipping malformed video entry: " + e.getMessage());
            }
        }

        return videoList;
    }

    // Save list of videos to file
    private static void saveDatabase(List<Video> videoList) throws IOException {
        VideoDBWrapper wrapper = new VideoDBWrapper(videoList);
        JsonIO.writeFormattedObject(wrapper, new File(DATABASE_FILE));
    }

    // Retrieve the encrypted file path for a given video name
    public static File getVideoFile(String videoName) {
        try {
            List<Video> videoList = loadDatabase();
            for (Video v : videoList) {
                if (v.getVideoName().equalsIgnoreCase(videoName)) {
                    Path path = v.getEncryptedPath();
                    return path.toFile();
                }
            }
        } catch (IOException e) {
            System.err.println("[videodatabase] Failed to load database: " + e.getMessage());
        }
        System.err.println("[videodatabase] Video not found: " + videoName);
        return null;
    }

    // NEW: Retrieve the video category for a given video name
    public static String getVideoCategory(String videoName) {
        try {
            List<Video> videoList = loadDatabase();
            for (Video v : videoList) {
                if (v.getVideoName().equalsIgnoreCase(videoName)) {
                    return v.getVideoCategory();
                }
            }
        } catch (IOException e) {
            System.err.println("[videodatabase] Failed to load database: " + e.getMessage());
        }
        System.err.println("[videodatabase] Video not found: " + videoName);
        return null;
    }

    // NEW: Retrieve the video age rating for a given video name
    public static String getVideoAgeRating(String videoName) {
        try {
            List<Video> videoList = loadDatabase();
            for (Video v : videoList) {
                if (v.getVideoName().equalsIgnoreCase(videoName)) {
                    return v.getVideoAgeRating();
                }
            }
        } catch (IOException e) {
            System.err.println("[videodatabase] Failed to load database: " + e.getMessage());
        }
        System.err.println("[videodatabase] Video not found: " + videoName);
        return null;
    }

    // NEW: Retrieve the full Video object for a given video name
    public static Video getVideo(String videoName) {
        try {
            List<Video> videoList = loadDatabase();
            for (Video v : videoList) {
                if (v.getVideoName().equalsIgnoreCase(videoName)) {
                    return v;
                }
            }
        } catch (IOException e) {
            System.err.println("[videodatabase] Failed to load database: " + e.getMessage());
        }
        System.err.println("[videodatabase] Video not found: " + videoName);
        return null;
    }

    // Retrieve all videos
    public static List<Video> getAllVideos() {
        try {
            return loadDatabase();
        } catch (IOException e) {
            System.err.println("[videodatabase] Error reading video database: " + e.getMessage());
            return new ArrayList<>();
        }
    }
}
