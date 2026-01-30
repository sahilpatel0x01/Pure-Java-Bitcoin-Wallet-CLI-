package crypto;

import java.math.BigInteger;
import java.util.Arrays;

public class Base58 {
    public static final char[] ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
    private static final int[] INDEXES = new int[128];

    static {
        Arrays.fill(INDEXES, -1);
        for (int i = 0; i < ALPHABET.length; i++) {
            INDEXES[ALPHABET[i]] = i;
        }
    }

    public static String encode(byte[] input) {
        if (input.length == 0) return "";
        
        // Count leading zeros
        int zeros = 0;
        while (zeros < input.length && input[zeros] == 0) {
            zeros++;
        }
        
        // Convert to BigInteger
        byte[] temp = new byte[input.length];
        System.arraycopy(input, 0, temp, 0, input.length); // copy to avoid modifying input if we need that? actually input is treated as ubyte
        // BigInteger requires positive sign, so we rely on constructor
        BigInteger b = new BigInteger(1, input);
        
        StringBuilder sb = new StringBuilder();
        BigInteger base = BigInteger.valueOf(58);
        
        while (b.compareTo(BigInteger.ZERO) > 0) {
            BigInteger[] divRem = b.divideAndRemainder(base);
            sb.append(ALPHABET[divRem[1].intValue()]);
            b = divRem[0];
        }
        
        // Append leading zeros
        for (int i = 0; i < zeros; i++) {
            sb.append(ALPHABET[0]);
        }
        
        return sb.reverse().toString();
    }

    public static byte[] decode(String input) {
        if (input.length() == 0) return new byte[0];
        
        // Convert base58 string to BigInteger
        BigInteger b = BigInteger.ZERO;
        BigInteger base = BigInteger.valueOf(58);
        
        int zeros = 0;
        boolean parsingLeadingZeros = true;
        
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            int digit = c < 128 ? INDEXES[c] : -1;
            if (digit == -1) throw new IllegalArgumentException("Invalid Base58 character: " + c);
            
            if (parsingLeadingZeros && digit == 0) {
                zeros++;
            } else {
                parsingLeadingZeros = false;
            }
            
            b = b.multiply(base).add(BigInteger.valueOf(digit));
        }
        
        byte[] bBytes = b.toByteArray();
        // Remove sign byte if present (BigInteger might add a leading 0 byte to signify positive)
        boolean stripSignByte = bBytes.length > 1 && bBytes[0] == 0 && bBytes[1] < 0; // Wait, BigInteger toByteArray is signed 2's complement.
        // Actually simpler: 
        if (bBytes[0] == 0) {
             bBytes = Arrays.copyOfRange(bBytes, 1, bBytes.length);
        }
        
        byte[] result = new byte[zeros + bBytes.length];
        System.arraycopy(bBytes, 0, result, zeros, bBytes.length);
        return result;
    }
    
    public static String encodeCheck(byte[] payload) {
        byte[] checksum = HashUtils.doubleSha256(payload, 0, payload.length);
        byte[] combined = new byte[payload.length + 4];
        System.arraycopy(payload, 0, combined, 0, payload.length);
        System.arraycopy(checksum, 0, combined, payload.length, 4);
        return encode(combined);
    }
}
