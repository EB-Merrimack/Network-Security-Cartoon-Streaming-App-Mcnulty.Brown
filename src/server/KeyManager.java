package server;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class KeyManager {

    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }
}