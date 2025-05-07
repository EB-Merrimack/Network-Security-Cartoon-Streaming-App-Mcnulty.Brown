package common.protocol.messages;

import merrimackutil.json.types.*;
import common.protocol.Message;
import java.io.InvalidObjectException;

/**
 * Represents a message that provides a response to a file download request.
 * Implements the {@link Message} interface.
 */
public class DownloadResponseMessage implements Message {
    private String videocatagory;
    private String videoname;
    private String videoagerating;
    private String encryptedVideo;
    private String encryptedAESKey;
    private String iv;
    private String savePath; // New field to store the save path

     /**
     * Default constructor for DownloadResponseMessage.
     */
    public DownloadResponseMessage() {}

    /**
     * Constructs a new DownloadResponseMessage with the specified parameters.
     *
     * @param videocatagory the category of the video.
     * @param videoname the name of the video.
     * @param videoagerating the age rating of the video.
     * @param encryptedAESKey the encrypted AES key used for decryption.
     * @param iv the initialization vector for the encryption.
     * @param savePath the path where the video should be saved.
     */
    public DownloadResponseMessage(
        String videocatagory,
        String videoname,
        String videoagerating,
        String encryptedAESKey,
        String iv,
        String savePath  // New parameter for save path
    ) {
        this.videocatagory = videocatagory;
        this.videoname = videoname;
        this.videoagerating = videoagerating;
        this.encryptedAESKey = encryptedAESKey;
        this.iv = iv;
        this.savePath = savePath; // Initialize the savePath
    }

    /**
     * Gets the encrypted video data.
     *
     * @return the encrypted video as a string.
     */
    public String getEncryptedVideo() {
        return encryptedVideo;
    }

    /**
     * Gets the category of the video.
     *
     * @return the video category.
     */
    public String getVideocatagory() {
        return videocatagory;
    }

     /**
     * Gets the name of the video.
     *
     * @return the video name.
     */
    public String getVideoname() {
        return videoname;
    }

    /**
     * Gets the age rating of the video.
     *
     * @return the video age rating.
     */
    public String getVideoagerating() {
        return videoagerating;
    }

    /**
     * Gets the type of the message, which is "DownloadResponse".
     *
     * @return the message type.
     */
    @Override
    public String getType() {
        return "DownloadResponse";
    }

    /**
     * Gets the encrypted AES key used for decryption.
     *
     * @return the encrypted AES key.
     */
    public String getEncryptedAESKey() {
        return encryptedAESKey;
    }

    /**
     * Gets the initialization vector used for encryption.
     *
     * @return the initialization vector.
     */
    public String getIv() {
        return iv;
    }

    /**
     * Gets the save path where the video should be saved.
     *
     * @return the save path.
     */
    public String getSavePath() {
        return savePath; // Return the save path
    }

    /**
     * Converts this DownloadResponseMessage into a JSON object.
     *
     * @return a JSONObject representing this message.
     */
    @Override
    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();
        obj.put("type", getType());
        obj.put("videocatagory", videocatagory);
        obj.put("videoname", videoname);
        obj.put("videoagerating", videoagerating);
        obj.put("encryptedAESKey", encryptedAESKey);
        obj.put("iv", iv);
        obj.put("savePath", savePath); // Include save path in the JSON
        return obj;
    }

    /**
     * Deserializes the given JSON object into this DownloadResponseMessage.
     *
     * @param type the JSON object containing the data to deserialize.
     * @throws InvalidObjectException if the object is not a valid JSON object or contains invalid data.
     */
    @Override
    public void deserialize(JSONType type) throws InvalidObjectException {
        if (!(type instanceof JSONObject)) throw new InvalidObjectException("Expected JSONObject.");
        JSONObject obj = (JSONObject) type;
        videocatagory = obj.getString("videocatagory");
        videoname = obj.getString("videoname");
        videoagerating = obj.getString("videoagerating");
        encryptedAESKey = obj.getString("encryptedAESKey");
        iv = obj.getString("iv");
        savePath = obj.getString("savePath"); // Deserialize savePath
    }

    /**
     * Decodes the provided JSON object into a DownloadResponseMessage.
     *
     * @param obj the JSON object to decode.
     * @return a new DownloadResponseMessage decoded from the JSON object.
     * @throws InvalidObjectException if the JSON object is invalid.
     */
    @Override
    public Message decode(JSONObject obj) throws InvalidObjectException {
        DownloadResponseMessage msg = new DownloadResponseMessage();
        msg.deserialize(obj);
        return msg;
    }
}
