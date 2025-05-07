package server.Admin;

import common.protocol.messages.AdminAuth;
import common.protocol.user_auth.TOTP;
import java.security.MessageDigest;
import java.util.Base64;

public class AdminAuthenticator {

    private static final boolean DEBUG = true;

    /**
     * Authenticate the static admin.
     *
     * @param msg the AuthenticateMessage
     * @return true if authenticated; false otherwise
     */
    public static boolean authenticate(AdminAuth msg) {

        try {
            String username = msg.getUser();
            String password = msg.getPass();
            String otp = msg.getOtp();

          

            // 1. Check username
            Admin admin = Admin.getInstance(); // Always reference the singleton Admin instance

            if (admin == null) {
                return false;
            }

            if (!admin.getUser().equals(username)) {
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


            if (!MessageDigest.isEqual(passwordHash.getBytes(), admin.getPass().getBytes())) {
                return false;
            }

            // 3. Validate OTP
            boolean otpValid = verifyTOTP(admin.getTotpKey(), otp);
            return otpValid;

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

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
