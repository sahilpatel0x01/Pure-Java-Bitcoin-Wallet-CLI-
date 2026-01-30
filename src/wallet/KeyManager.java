package wallet;

import crypto.Base58;
import crypto.HashUtils;
import crypto.Secp256k1;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class KeyManager {

    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * Generates a new random private key (32 bytes).
     * Ensures the key is valid (0 < key < n).
     */
    public static byte[] generatePrivateKey() {
        BigInteger n = Secp256k1.n;
        BigInteger d;
        do {
            d = new BigInteger(256, secureRandom);
        } while (d.signum() == 0 || d.compareTo(n) >= 0);
        
        byte[] bytes = d.toByteArray();
        if (bytes.length == 32) return bytes;
        
        // Adjust to ensure exactly 32 bytes
        byte[] result = new byte[32];
        if (bytes.length > 32) {
            // Trim (likely sign byte)
            System.arraycopy(bytes, bytes.length - 32, result, 0, 32);
        } else {
             // Pad
             System.arraycopy(bytes, 0, result, 32 - bytes.length, bytes.length);
        }
        return result;
    }

    /**
     * Gets the public key from a private key.
     * @param privateKey 32-byte private key
     * @param compressed Whether to use compressed format
     * @return Public key bytes
     */
    public static byte[] getPublicKey(byte[] privateKey, boolean compressed) {
        BigInteger priv = new BigInteger(1, privateKey);
        return Secp256k1.getPublicKey(priv, compressed);
    }

    /**
     * Generates a P2PKH address from a public key.
     * @param publicKey Public key bytes
     * @param textnet If true, uses testnet prefix (0x6f), else mainnet (0x00)
     * @return Base58Check encoded address
     */
    public static String getAddress(byte[] publicKey, boolean testnet) {
        byte[] hash160 = HashUtils.hash160(publicKey);
        byte[] versionedPayload = new byte[1 + hash160.length];
        versionedPayload[0] = (byte) (testnet ? 0x6F : 0x00);
        System.arraycopy(hash160, 0, versionedPayload, 1, hash160.length);
        return Base58.encodeCheck(versionedPayload);
    }

    /**
     * Encodes a private key to WIF (Wallet Import Format).
     * @param privateKey 32-byte private key
     * @param compressed Whether the corresponding public key is compressed
     * @param testnet If true, uses testnet prefix (0xef), else mainnet (0x80)
     * @return WIF string
     */
    public static String privateKeyToWIF(byte[] privateKey, boolean compressed, boolean testnet) {
        byte prefix = (byte) (testnet ? 0xEF : 0x80);
        int length = 1 + 32 + (compressed ? 1 : 0);
        byte[] payload = new byte[length];
        payload[0] = prefix;
        System.arraycopy(privateKey, 0, payload, 1, 32);
        if (compressed) {
            payload[33] = 0x01;
        }
        return Base58.encodeCheck(payload);
    }

    /**
     * Decodes a WIF private key.
     * @param wif WIF string
     * @return ParsedPrivateKey containing key bytes and compression flag
     */
    public static ParsedPrivateKey wifToPrivateKey(String wif) {
        byte[] decoded = Base58.decode(wif);
        // Verify checksum is handled by some Base58 decodeCheck? 
        // Base58.decode just decodes. We should verify checksum manually or implement decodeCheck.
        // My Base58.java doesn't have decodeCheck, let's implement validation here.
        
        if (decoded.length < 4) throw new IllegalArgumentException("Invalid WIF length");
        
        byte[] data = Arrays.copyOfRange(decoded, 0, decoded.length - 4);
        byte[] checksum = Arrays.copyOfRange(decoded, decoded.length - 4, decoded.length);
        byte[] calculatedChecksum = HashUtils.doubleSha256(data, 0, data.length);
        byte[] calculatedChecksumFirst4 = Arrays.copyOfRange(calculatedChecksum, 0, 4);
        
        if (!Arrays.equals(checksum, calculatedChecksumFirst4)) {
            throw new IllegalArgumentException("Invalid WIF checksum");
        }
        
        byte prefix = data[0]; // 0x80 for mainnet, 0xef for testnet
        // We can check prefix if we want strictness
        
        byte[] key = new byte[32];
        boolean compressed = false;
        
        System.arraycopy(data, 1, key, 0, 32);
        
        if (data.length == 34) {
             if (data[33] != 0x01) throw new IllegalArgumentException("Invalid WIF compression flag");
             compressed = true;
        } else if (data.length != 33) {
             throw new IllegalArgumentException("Invalid WIF length: " + data.length);
        }
        
        return new ParsedPrivateKey(key, compressed);
    }
    
    public static class ParsedPrivateKey {
        public final byte[] key;
        public final boolean compressed;
        
        public ParsedPrivateKey(byte[] key, boolean compressed) {
            this.key = key;
            this.compressed = compressed;
        }
    }
}
