package com.example.legacyapp.util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Utility class for signing and verifying cookies using HMAC-SHA256.
 * Java 6 compatible implementation without external dependencies.
 * 
 * <p>Cookie values are URL-encoded and signed to prevent tampering. 
 * The signed cookie format is: {urlEncodedValue}:{signature}</p>
 * 
 * <p>Configuration via system property: cookie.secret.key</p>
 * If not configured, a random key is generated at startup (with warning).
 * 
 * @author Legacy App Integration
 * @version 1.0
 */
public class CookieSigningUtil {
    
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String SEPARATOR = ":";
    private static final String SECRET_KEY_PROPERTY = "cookie.secret.key";
    private static final String ENCODING = "UTF-8";
    
    private static String secretKey;
    private static boolean keyConfigured = false;
    
    // Initialize secret key on class load
    static {
        secretKey = System.getProperty(SECRET_KEY_PROPERTY);
        if (secretKey == null || secretKey.length() == 0) {
            // Generate random secret key
            secretKey = generateRandomKey();
            keyConfigured = false;
            System.err.println("WARNING: Cookie secret key not configured. Using randomly generated key.");
            System.err.println("WARNING: Set system property 'cookie.secret.key' for production use.");
            System.err.println("WARNING: Random key will be different on each server restart.");
        } else {
            keyConfigured = true;
            System.out.println("CookieSigningUtil: Secret key configured from system property");
        }
    }
    
    /**
     * Sign a cookie value using HMAC-SHA256.
     * 
     * @param value the value to sign
     * @return signed value in format: {urlEncodedValue}:{signature}
     */
    public static String signCookie(String value) {
        if (value == null || value.length() == 0) {
            throw new IllegalArgumentException("Cookie value cannot be null or empty");
        }
        
        try {
            // URL-encode the value to prevent separator conflicts
            String encodedValue = URLEncoder.encode(value, ENCODING);
            String signature = calculateHmac(encodedValue);
            return encodedValue + SEPARATOR + signature;
        } catch (Exception e) {
            System.err.println("CookieSigningUtil: Failed to sign cookie: " + e.getMessage());
            throw new RuntimeException("Failed to sign cookie", e);
        }
    }
    
    /**
     * Verify and extract the original value from a signed cookie.
     * 
     * @param signedValue the signed cookie value in format: {urlEncodedValue}:{signature}
     * @return the original decoded value if signature is valid, null otherwise
     */
    public static String verifyAndExtractCookie(String signedValue) {
        if (signedValue == null || signedValue.length() == 0) {
            return null;
        }
        
        // Split signed value into encoded value and signature
        int separatorIndex = signedValue.lastIndexOf(SEPARATOR);
        if (separatorIndex < 0) {
            System.err.println("CookieSigningUtil: Invalid signed cookie format (missing separator)");
            return null;
        }
        
        String encodedValue = signedValue.substring(0, separatorIndex);
        String providedSignature = signedValue.substring(separatorIndex + 1);
        
        try {
            // Calculate expected signature
            String expectedSignature = calculateHmac(encodedValue);
            
            // Compare signatures (timing-safe comparison)
            if (secureEquals(expectedSignature, providedSignature)) {
                // Decode the value before returning
                return URLDecoder.decode(encodedValue, ENCODING);
            } else {
                System.err.println("CookieSigningUtil: Cookie signature verification failed");
                return null;
            }
        } catch (Exception e) {
            System.err.println("CookieSigningUtil: Failed to verify cookie: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Calculate HMAC-SHA256 signature for a value.
     */
    private static String calculateHmac(String value) 
            throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {
        
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(ENCODING), HMAC_ALGORITHM);
        mac.init(keySpec);
        
        byte[] rawHmac = mac.doFinal(value.getBytes(ENCODING));
        return bytesToHex(rawHmac);
    }
    
    /**
     * Convert byte array to hex string.
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(0xff & bytes[i]);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
    
    /**
     * Timing-safe string comparison to prevent timing attacks.
     */
    private static boolean secureEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        
        if (a.length() != b.length()) {
            return false;
        }
        
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }
    
    /**
     * Generate a random secret key for cookie signing.
     */
    private static String generateRandomKey() {
        SecureRandom random = new SecureRandom();
        byte[] keyBytes = new byte[32]; // 256 bits
        random.nextBytes(keyBytes);
        return bytesToHex(keyBytes);
    }
    
    /**
     * Check if secret key was configured (vs randomly generated).
     */
    public static boolean isKeyConfigured() {
        return keyConfigured;
    }
}
