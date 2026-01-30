package crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashUtils {

    public static byte[] sha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    public static byte[] sha256(byte[] data, int offset, int length) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(data, offset, length);
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    public static byte[] ripemd160(byte[] data) {
        Ripemd160 digest = new Ripemd160();
        digest.update(data, 0, data.length);
        byte[] out = new byte[20];
        digest.doFinal(out, 0);
        return out;
    }

    public static byte[] hash160(byte[] data) {
        return ripemd160(sha256(data));
    }

    public static byte[] doubleSha256(byte[] data) {
        return sha256(sha256(data));
    }
    
    public static byte[] doubleSha256(byte[] data, int offset, int length) {
        return sha256(sha256(data, offset, length));
    }
}
