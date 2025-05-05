package server.Admin;

import common.protocol.messages.AuthenticateMessage;
import common.protocol.user_auth.TOTP;

import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;

public class AdminAuthenticationHandler {

    // Static admin instance (hardcoded data)
    private static final Admin admin = new Admin(
        "<salt>",
        "<passwordHash>",
        "<totpKey>",
        "<user>",
        "<pubkey>",
        "<encryptedAESKey>",
        "<aesIV>"
    );

    private static final boolean DEBUG = false;

    /**
     * Authenticate the static admin.
     *
     * @param message the AuthenticateMessage
     * @return true if authenticated; false otherwise
     */
    public static boolean authenticate(AuthenticateMessage message) {
        try {
            String username = message.getUser();
            String password = message.getPass();
            String otp = message.getOtp();

            if (DEBUG) {
                System.out.println("[DEBUG] AuthenticateRequest - user: " + username + ", password: " + password + ", otp: " + otp);
            }

            // 1. Check username
            if (!admin.getUser().equals(username)) {
                if (DEBUG) System.out.println("[DEBUG] Username mismatch.");
                return false;
            }

            // 2. Validate password
            byte[] saltBytes = Base64.getDecoder().decode(admin.getSalt());
            byte[] hash = org.bouncycastle.crypto.generators.SCrypt.generate(
                password.getBytes(), 
                saltBytes, 
                2048, 
                8, 
                1, 
                16
            );
            String passwordHash = Base64.getEncoder().encodeToString(hash);

            if (DEBUG) {
                System.out.println("[DEBUG] Calculated password hash: " + passwordHash);
            }

            if (!MessageDigest.isEqual(passwordHash.getBytes(), admin.getPass().getBytes())) {
                if (DEBUG) System.out.println("[DEBUG] Password hash mismatch.");
                return false;
            }

            // 3. Validate OTP
            boolean otpValid = verifyTOTP(admin.getTotpKey(), otp);

            if (DEBUG) {
                System.out.println("[DEBUG] OTP validation result: " + otpValid);
            }

            return otpValid;

        } catch (Exception e) {
            if (DEBUG) {
                System.out.println("[DEBUG] Authentication error: " + e.getMessage());
            }
            e.printStackTrace();
            return false;
        }
    }

    private static boolean verifyTOTP(String base64Secret, String otp) {
        try {
            byte[] key = Base64.getDecoder().decode(base64Secret);
            long timeIndex = Instant.now().getEpochSecond() / 30;

            for (int i = -3; i <= 3; i++) {
                String candidate = TOTP.generateTOTP(key, timeIndex + i);
                if (candidate.equals(otp)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }
}
