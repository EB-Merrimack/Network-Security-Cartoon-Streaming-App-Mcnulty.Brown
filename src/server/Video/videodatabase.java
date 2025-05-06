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

        /**
         * Converts the object to a JSON type.
         * @return a JSON type either JSONObject or JSONArray.
         * The returned JSONObject contains the videos field.
         * The videos field is a JSONArray of Video JSONTypes.
         *
         * The JSON object is structured as follows:
         *
         * {
         *     "videos": [
         *         {
         *             "encryptedPath": string,
         *             "videoName": string,
         *             "videoCategory": string,
         *             "videoAgeRating": string
         *         },
         *         ...
         *     ]
         * }
         */
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

        /**
         * Deserialize a JSON object into a VideoDBWrapper instance.
         * 
         * @param obj the JSON object to deserialize
         * @throws InvalidObjectException if the object is not a JSON object
         */
        @Override
        public void deserialize(JSONType obj) {
            // unused
        }
    }

    /**
     * Inserts a new video into the database.
     * 
     * @param encryptedPath The Path to the encrypted video file.
     * @param videoName The name of the video.
     * @param videoCategory The category of the video.
     * @param videoAgeRating The age rating of the video.
     */
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

    /**
     * Load video database into a list.
     * 
     * @return a list of Video objects
     * @throws IOException if there is an error reading the database file
     */
    private static List<Video> loadDatabase() throws IOException {
        List<Video> videoList = new ArrayList<>();
        File dbFile = new File(DATABASE_FILE);

        if (!dbFile.exists()) {
            return videoList;
        }

        JSONObject root = JsonIO.readObject(dbFile);
        JSONArray videos = root.getArray("videos");

        // Iterate over the JSON array and deserialize each entry
        for (int i = 0; i < videos.size(); i++) {
            JSONType entry = (JSONType) videos.get(i);
            Video v = new Video();
            try {
                // Attempt to deserialize each entry
                v.deserialize(entry);
                videoList.add(v);
            } catch (InvalidObjectException e) {
                // If deserialization fails, skip this entry and log an error
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

    /**
     * Retrieve the encrypted file path for a given video name.
     *
     * @param videoName The name of the video.
     * @return The File object representing the encrypted video file, or null if not found.
     */
    public static File getVideoFile(String videoName) {
        try {
            // Load the video database into a list
            List<Video> videoList = loadDatabase();
            
            // Iterate through the video list to find the matching video name
            for (Video v : videoList) {
                if (v.getVideoName().equalsIgnoreCase(videoName)) {
                    // Get the encrypted path and convert it to File
                    Path path = v.getEncryptedPath();
                    return path.toFile();
                }
            }
        } catch (IOException e) {
            // Handle any I/O exceptions that occur during database loading
            System.err.println("[videodatabase] Failed to load database: " + e.getMessage());
        }
        // Print an error message if the video is not found
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
