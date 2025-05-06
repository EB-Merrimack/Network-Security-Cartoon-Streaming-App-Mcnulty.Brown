package server;

import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;
import merrimackutil.json.JSONSerializable;

import java.io.File;
import java.io.IOException;
import java.io.InvalidObjectException;

/**
 * This class represents the configuration data for the bulletin board service.
 */
public class Configuration implements JSONSerializable
{
  private int port;
  private static String usersFile;
  private static String Videofolder;
  private String keystoreFile;
  private String keystorePass;
  private String configDir;
  private static String adminFile;
  private static String videoDatabase; 

  

  /**
   * Constructs a configuration object from the appropriate JSON Object.
   * @param config the JSON formatted configuration object.
   * @throws InvalidObjectException if the config object is not valid.
   */
  public Configuration(JSONObject config) throws InvalidObjectException
  {
    deserialize(config);
  }

  /**
   * Gets the port number from the configuration file.
   * @return the port number the server should bind to.
   */
  public int getPort()
  {
    return this.port;
  }

  /**
   * Get the path to the admin database file.
   * @return the file path as a string.
   */
  public static String getAdminFile() {
    return adminFile;
  }
  /**
     * Get the path to the video database file.
     * @return the file path as a string.
     */
    public static String getVideoDatabase() {
      return videoDatabase;
  }

  /**
   * Get the path to the users database file.
   * @return the file path as a string.
   */
  public static String getUsersFile()
  {
    return usersFile;
  }

  /**
   * Get the path to the bulletin board file.
   * @return the file path as a string.
   */
  public static String getVideofolder()
  {
    return Videofolder;
  }

  /**
   * Get the keystore filename.
   * @return the keystore file path.
   */
  public String getKeystoreFile() {
    try {
        return new File(configDir, keystoreFile).getCanonicalPath(); // ✅ this resolves ".." and symlinks
    } catch (IOException e) {
        throw new RuntimeException("Failed to resolve keystore path", e);
    }
}

  /**
   * Get the keystore password.
   * @return the keystore password.
   */
  public String getKeystorePass()
  {
    return keystorePass;
  }

  /**
   * Sets the configuration directory for this configuration object.
   * @param path the directory path as a string.
   */
  public void setConfigDir(String path) 
  {
    this.configDir = path;
  }

  /**
   * Converts JSON data to an object of this type.
   * 
   * This method deserializes a JSONType object into its corresponding fields.
   * It verifies that the JSON object contains the necessary keys and assigns
   * the values to the fields of this configuration object.
   *
   * @param obj a JSON type to deserialize.
   * @throws InvalidObjectException if the type does not match this object or 
   *                                if required keys are missing.
   */
  public void deserialize(JSONType obj) throws InvalidObjectException {
      // Define the expected keys for the configuration
      String[] keys = {
          "port", "users-file", "Videofolder",
          "keystore-file", "keystore-pass", "admin-file", "videoDatabase"
      };

      // Check if the input JSONType is a JSONObject
      if (obj.isObject()) {
          JSONObject config = (JSONObject) obj;

          // Verify that the JSON object contains all required keys
          config.checkValidity(keys);

          // Assign JSON values to the configuration fields
          port = config.getInt("port");
          usersFile = config.getString("users-file");
          Videofolder = config.getString("Videofolder");
          keystoreFile = config.getString("keystore-file");
          keystorePass = config.getString("keystore-pass");
          adminFile = config.getString("admin-file");
          videoDatabase = config.getString("videoDatabase");

      } else {
          // Throw an exception if the JSONType is not a JSONObject
          throw new InvalidObjectException(
              "Configuration -- received array, expected Object."
          );
      }
  }
  
  /**
   * Converts the object to a JSON type.
   * @return a JSON type either JSONObject or JSONArray.
   */
  public JSONType toJSONType()
  {
    JSONObject obj = new JSONObject();

    obj.put("port", port);
    obj.put("users-file", usersFile);
    obj.put("Videofolder", Videofolder);
    obj.put("keystore-file", keystoreFile);
    obj.put("keystore-pass", keystorePass);
    obj.put("admin-file", adminFile);
    obj.put("videoDatabase", videoDatabase);
    return obj;
  }
}
