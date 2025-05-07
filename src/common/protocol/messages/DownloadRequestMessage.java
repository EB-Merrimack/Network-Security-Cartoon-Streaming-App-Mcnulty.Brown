package common.protocol.messages;

import merrimackutil.json.types.*;
import common.protocol.Message;
import java.io.InvalidObjectException;
import java.util.Base64;

/**
 * Represents a message requesting a file download.
 * Implements the {@link Message} interface.
 */
public class DownloadRequestMessage implements Message {
    private String filename;
    private String username; 
    private byte[] privKeyBytes;
    private String savePath; // <-- Added field

    /**
     * Default constructor for DownloadRequestMessage.
     */
    public DownloadRequestMessage() {}

    /**
     * Constructs a new DownloadRequestMessage with the specified parameters.
     *
     * @param filename the name of the file being requested.
     * @param username the username of the requesting user.
     * @param privKeyBytes the private key associated with the request, in byte array form.
     * @param savePath the path where the file should be saved.
     */
    public DownloadRequestMessage(String filename, String username, byte[] privKeyBytes, String savePath) {
        this.filename = filename;
        this.username = username;
        this.privKeyBytes = privKeyBytes;
        this.savePath = savePath; // <-- Store savePath
    }

     /**
     * Gets the filename for the download request.
     *
     * @return the filename being requested.
     */
    public String getFilename() {
        return filename;
    }

    /**
     * Gets the username of the user making the download request.
     *
     * @return the username of the requesting user.
     */
    public String getUsername() {
        return username;
    }

    /**
     * Gets the private key bytes associated with the request.
     *
     * @return the private key bytes.
     */
    public byte[] getPrivKeyBytes() {
        System.out.println("[INFO] DownloadRequestMessage.getPrivKeyBytes(): " + java.util.Arrays.toString(privKeyBytes));
        return privKeyBytes;
    }

    /**
     * Gets the save path where the file should be saved.
     *
     * @return the save path.
     */
    public String getSavePath() { // <-- Getter
        return savePath;
    }

    /**
     * Deserializes the given JSON object into this DownloadRequestMessage.
     *
     * @param obj the JSON object containing the data to deserialize.
     * @throws InvalidObjectException if the object is not a valid JSON object or contains invalid data.
     */
    @Override
    public void deserialize(JSONType obj) throws InvalidObjectException {
        if (!(obj instanceof JSONObject)) {
            throw new InvalidObjectException("Expected JSONObject");
        }
        JSONObject json = (JSONObject) obj;
        this.filename = json.getString("filename");
        this.username = json.getString("username");
        this.privKeyBytes = Base64.getDecoder().decode(json.getString("privKeyBytes"));
        this.savePath = json.getString("savePath"); // <-- Deserialize savePath
    }

    /**
     * Converts this DownloadRequestMessage into a JSON object.
     *
     * @return a JSONObject representing this message.
     */
    @Override
    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();
        obj.put("type", "DownloadRequest");
        obj.put("filename", filename);
        obj.put("username", username);
        obj.put("privKeyBytes", Base64.getEncoder().encodeToString(privKeyBytes));
        obj.put("savePath", savePath); // <-- Serialize savePath
        return obj;
    }

    /**
     * Gets the type of message. This will return "DownloadRequest".
     *
     * @return the type of the message.
     */
    @Override
    public String getType() {
        return "DownloadRequest";
    }

    /**
     * Decodes the provided JSON object into a DownloadRequestMessage.
     *
     * @param obj the JSON object to decode.
     * @return a new DownloadRequestMessage decoded from the JSON object.
     * @throws InvalidObjectException if the JSON object is invalid.
     */
    @Override
    public Message decode(JSONObject obj) throws InvalidObjectException {
        DownloadRequestMessage msg = new DownloadRequestMessage();
        msg.deserialize(obj);
        return msg;
    }

    /**
     * Returns a string representation of this DownloadRequestMessage.
     *
     * @return a string describing the DownloadRequestMessage.
     */
    @Override
    public String toString() {
        return "[DownloadRequestMessage] filename=" + filename +
               ", username=" + username +
               ", privKeyBytes=" + java.util.Arrays.toString(privKeyBytes) +
               ", savePath=" + savePath; // <-- Print savePath too
    }
}
