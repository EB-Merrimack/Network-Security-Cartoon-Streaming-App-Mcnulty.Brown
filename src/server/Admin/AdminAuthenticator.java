package server.Admin;

import common.protocol.messages.AdminAuth;
import common.protocol.user_auth.TOTP;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * Handles the authentication of the admin user using username, password, and One-Time Password (OTP).
 * This class provides methods to verify the admin credentials, including validating the password and OTP.
 */
public class AdminAuthenticator {

    private static final boolean DEBUG = true; //debug flad to control debug prints

    /**
     * Authenticate the static admin.
     *
     * @param msg the AuthenticateMessage
     * @return true if authenticated; false otherwise
     */
    public static boolean authenticate(AdminAuth msg) {
        System.out.println("[DEBUG] Authenticating admin...");

        try {
            String username = msg.getUser();
            String password = msg.getPass();
            String otp = msg.getOtp();

            if (DEBUG) {
                System.out.println("[DEBUG] AuthenticateRequest - user: " + username + ", password: " + password + ", otp: " + otp);
            }

            // 1. Check username
            Admin admin = Admin.getInstance(); // Always reference the singleton Admin instance

            if (admin == null) {
                if (DEBUG) System.out.println("[DEBUG] Admin is not initialized.");
                return false;
            }

            if (!admin.getUser().equals(username)) {
                if (DEBUG) System.out.println("[DEBUG] Username mismatch.");
                return false;
            }

            // 2. Validate password
            byte[] saltBytes = Base64.getDecoder().decode(admin.getSalt());
            byte[] hash = org.bouncycastle.crypto.generators.SCrypt.generate(
                password.getBytes(),
                saltBytes,
                2048, // Cost factor
                8,    // Block size
                1,    // Parallelization factor
                16    // Output length
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

    /**
     * Verifies the provided OTP (One-Time Password) against the expected OTP using the TOTP algorithm.
     * This method checks the OTP for the current time and up to 3 intervals before and after.
     *
     * @param base64Secret the base64 encoded secret key for generating the OTP.
     * @param otp the OTP provided by the user.
     * @return true if the OTP is valid; false otherwise.
     */
    private static boolean verifyTOTP(String base64Secret, String otp) {
        try {
            byte[] key = Base64.getDecoder().decode(base64Secret);
            long timeIndex = System.currentTimeMillis() / 1000L / 30;

            // Checking TOTP for the current time and +/- 3 intervals
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
