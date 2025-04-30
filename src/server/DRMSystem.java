package server;
import javax.crypto.SecretKey;

import common.CryptoUtils;

// DRM logic example
public class DRMSystem {

    public void protectContent(String content) throws Exception {
        SecretKey key = KeyManager.generateKey();
        byte[] encryptedContent = CryptoUtils.encrypt(content, key);
        // Store encrypted content and key securely
    }
}
