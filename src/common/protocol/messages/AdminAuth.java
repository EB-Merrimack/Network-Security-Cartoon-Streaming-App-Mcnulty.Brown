/* 
 * Copyright (C) 2025  Emily J Brown And Erin Mcnulty
 *
  * The {@code AdminAuth} class represents an authentication message used to verify an admin user
 * by sending their username, password, and one-time password (OTP). This message is serialized to 
 * JSON format for transmission and can be deserialized back to an object. It is part of the 
 * authentication process, ensuring secure communication between the admin client and the server.
 * 
 * It includes methods for:
 * - Getting the username, password, and OTP.
 * - Serializing and deserializing the message to and from JSON.
 * - Providing a string representation of the message.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation, either version 3 of the License, or 
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package common.protocol.messages;

import merrimackutil.json.types.*;
import common.protocol.Message;

import java.io.InvalidObjectException;

/**
 * A message used to authenticate a user with a username, password, and OTP.
 */
public class AdminAuth implements Message {

    private String user;
    private String pass;
    private String otp;

    // Empty constructor for deserialization
    public AdminAuth() {}

    // Constructor for sending
    public AdminAuth(String user, String pass, String otp) {
        this.user = user;
        this.pass = pass;
        this.otp = otp;
    }

    /**
     * Returns the username associated with this authentication message.
     * @return the username associated with this authentication message
     */
    public String getUser() {
        return user;
    }

/**
 * Returns the password associated with this authentication message.
 * @return the password associated with this authentication message
 */

    public String getPass() {
        return pass;
    }

    /**
     * Returns the one-time password associated with this authentication message.
     * @return the one-time password associated with this authentication message
     */
    public String getOtp() {
        return otp;
    }

 

/**
 * Deserializes a JSON object into an AuthenticateMessage instance.
 *
 * @param obj the JSON object to deserialize
 * @throws InvalidObjectException if the object is not a valid JSONObject
 */

    @Override
    public void deserialize(JSONType obj) throws InvalidObjectException {
        if (!(obj instanceof JSONObject)) {
            throw new InvalidObjectException("Expected JSONObject");
        }

        JSONObject json = (JSONObject) obj;
        this.user = json.getString("user");
        this.pass = json.getString("pass");
        this.otp = json.getString("otp");

     
    }

    /**
     * Converts the object to a JSON type.
     * @return a JSON type either JSONObject or JSONArray.
     */
    @Override
    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();
        obj.put("type", "AdminAuth");
        obj.put("user", user);
        obj.put("pass", pass);
        obj.put("otp", otp);


        return obj;
    }

   
    /**
     * Decodes a JSON object into an AdminAuth instance.
     *
     * @param obj the JSON object to decode
     * @return an AdminAuth instance
     * @throws InvalidObjectException if the object is not a valid JSONObject
     */
    @Override
    public Message decode(JSONObject obj) throws InvalidObjectException {
        String user = obj.getString("user");
        String pass = obj.getString("pass");
        String otp = obj.getString("otp");

       
        return new AdminAuth(user, pass, otp);
    }

    /**
     * Returns a string representation of the object.
     * @return a string representation of the object
     */
    @Override
    public String toString() {
        return "[AdminAuth] user=" + user + ", otp=" + otp;
    }

    @Override
    public String getType() {
        return "AdminAuth";
    }
}