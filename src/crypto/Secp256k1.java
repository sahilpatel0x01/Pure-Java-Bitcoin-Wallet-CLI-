package crypto;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Pure Java implementation of Secp256k1 Elliptic Curve Cryptography.
 * USES AFFINE COORDINATES FOR SIMPLICITY.
 * NOT SAFE FOR PRODUCTION SIGNING (Side-channel vulnerable).
 * SUFFICIENT FOR KEY GENERATION AND ADDRESS CREATION.
 */
public class Secp256k1 {
    // Curve parameters secp256k1
    // y^2 = x^3 + 7 mod p
    public static final BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    public static final BigInteger a = BigInteger.ZERO;
    public static final BigInteger b = BigInteger.valueOf(7);
    public static final BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    public static final BigInteger Gx = new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    public static final BigInteger Gy = new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);

    public static final Point G = new Point(Gx, Gy);

    /**
     * Elliptic Curve Point
     */
    public static class Point {
        public final BigInteger x;
        public final BigInteger y;

        public Point(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
        }

        public boolean isInfinity() {
            return x == null && y == null;
        }

        public static final Point INFINITY = new Point(null, null);
    }

    /**
     * Point addition: P + Q
     */
    public static Point add(Point P, Point Q) {
        if (P.isInfinity()) return Q;
        if (Q.isInfinity()) return P;

        if (P.x.equals(Q.x)) {
            if (P.y.equals(Q.y)) {
                return doublePoint(P);
            } else {
                return Point.INFINITY;
            }
        }

        // slope s = (yP - yQ) / (xP - xQ) mod p
        BigInteger s = P.y.subtract(Q.y).multiply(P.x.subtract(Q.x).modInverse(p)).mod(p);
        
        // xR = s^2 - xP - xQ mod p
        BigInteger xR = s.pow(2).subtract(P.x).subtract(Q.x).mod(p);
        
        // yR = s(xP - xR) - yP mod p
        BigInteger yR = s.multiply(P.x.subtract(xR)).subtract(P.y).mod(p);

        return new Point(xR, yR);
    }

    /**
     * Point doubling: 2P
     */
    public static Point doublePoint(Point P) {
        if (P.isInfinity()) return Point.INFINITY;

        // slope s = (3xP^2 + a) / (2yP) mod p
        // a = 0 for secp256k1
        BigInteger s = P.x.pow(2).multiply(BigInteger.valueOf(3))
                .multiply(P.y.multiply(BigInteger.valueOf(2)).modInverse(p)).mod(p);

        // xR = s^2 - 2xP mod p
        BigInteger xR = s.pow(2).subtract(P.x.multiply(BigInteger.valueOf(2))).mod(p);

        // yR = s(xP - xR) - yP mod p
        BigInteger yR = s.multiply(P.x.subtract(xR)).subtract(P.y).mod(p);

        return new Point(xR, yR);
    }

    /**
     * Scalar multiplication: k * P
     */
    public static Point multiply(BigInteger k, Point P) {
        Point R = Point.INFINITY;
        Point V = P;
        // Double-and-add algorithm
        for (int i = 0; i < k.bitLength(); i++) {
            if (k.testBit(i)) {
                R = add(R, V);
            }
            V = doublePoint(V);
        }
        return R;
    }

    /**
     * Generate Public Key from Private Key
     * @param privateKey 32-byte integer
     * @param compressed whether to use compressed public key format
     * @return serialised public key
     */
    public static byte[] getPublicKey(BigInteger privateKey, boolean compressed) {
        if (privateKey.compareTo(BigInteger.ONE) < 0 || privateKey.compareTo(n) >= 0) {
            throw new IllegalArgumentException("Private key out of range");
        }
        
        Point pub = multiply(privateKey, G);
        
        if (compressed) {
            byte[] x = bigIntegerTo32Bytes(pub.x);
            byte[] result = new byte[33];
            result[0] = (byte) (pub.y.testBit(0) ? 0x03 : 0x02); // 0x02 if even, 0x03 if odd
            System.arraycopy(x, 0, result, 1, 32);
            return result;
        } else {
            byte[] x = bigIntegerTo32Bytes(pub.x);
            byte[] y = bigIntegerTo32Bytes(pub.y);
            byte[] result = new byte[65];
            result[0] = 0x04;
            System.arraycopy(x, 0, result, 1, 32);
            System.arraycopy(y, 0, result, 33, 32);
            return result;
        }
    }
    
    // Helper to ensure 32-byte output
    private static byte[] bigIntegerTo32Bytes(BigInteger b) {
        byte[] array = b.toByteArray();
        if (array.length == 32) return array;
        if (array.length > 32 && array[0] == 0) {
             // Trim leading zero
             return Arrays.copyOfRange(array, 1, 33);
        }
        if (array.length < 32) {
            // Pad with zeros
            byte[] padded = new byte[32];
            System.arraycopy(array, 0, padded, 32 - array.length, array.length);
            return padded;
        }
        throw new IllegalArgumentException("BigInteger too large for 32 bytes");
    }
}
