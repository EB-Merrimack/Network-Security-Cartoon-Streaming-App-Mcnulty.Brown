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

  public static String getAdminFile() {
    return adminFile;
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

  public void setConfigDir(String path) 
  {
    this.configDir = path;
  }

  /**
   * Converts JSON data to an object of this type.
   * @param obj a JSON type to deserialize.
   * @throws InvalidObjectException the type does not match this object.
   */
  public void deserialize(JSONType obj) throws InvalidObjectException
  {
      JSONObject config;
      String[] keys = {
          "port", "users-file", "Videofolder",
          "keystore-file", "keystore-pass", "admin-file"
      };
  
      if (obj.isObject())
      {
          config = (JSONObject) obj;
  
          config.checkValidity(keys);
  
          port = config.getInt("port");
          usersFile = config.getString("users-file");
          Videofolder = config.getString("Videofolder");
          keystoreFile = config.getString("keystore-file");
          keystorePass = config.getString("keystore-pass");
          adminFile = config.getString("admin-file");
      }
  
          
      else
      {
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

    return obj;
  }
}
