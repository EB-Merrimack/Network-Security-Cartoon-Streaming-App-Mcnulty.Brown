package server.Video;

import java.nio.file.Path;
import java.nio.file.Paths;

public class Video {
    private final Path encryptedPath;
    private final String videoName;
    private final String videoCategory;
    private final String videoAgeRating;

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

    // Static method to create Video from fields stored in JSON
    public static Video fromJsonFields(String encryptedPathStr, String videoName, String videoCategory, String videoAgeRating) {
        Path path = Paths.get(encryptedPathStr);
        return new Video(path, videoName, videoCategory, videoAgeRating);
    }
}
