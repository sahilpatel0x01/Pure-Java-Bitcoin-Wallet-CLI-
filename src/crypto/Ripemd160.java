package crypto;

/**
 * Pure Java implementation of RIPEMD-160.
 * Derived from the Bouncy Castle implementation and standard reference.
 */
public class Ripemd160 {
    private static final int DIGEST_LENGTH = 20;

    // Initial state
    private int H0, H1, H2, H3, H4;
    private int[] X = new int[16];
    private int xOff;

    // Buffer for single byte updates
    private byte[] xBuf = new byte[4];
    private int xBufOff;

    private long byteCount;

    public Ripemd160() {
        reset();
    }

    public void update(byte[] in, int inOff, int len) {
        // fill the current word
        while ((xBufOff != 0) && (len > 0)) {
            update(in[inOff]);
            inOff++;
            len--;
        }

        // process whole words
        while (len > xBuf.length) {
            processWord(in, inOff);
            inOff += xBuf.length;
            len -= xBuf.length;
            byteCount += xBuf.length;
        }

        // load in the remainder
        while (len > 0) {
            update(in[inOff]);
            inOff++;
            len--;
        }
    }

    public void update(byte in) {
        xBuf[xBufOff++] = in;
        if (xBufOff == xBuf.length) {
            processWord(xBuf, 0);
            xBufOff = 0;
            byteCount += 4;
        }
    }

    private void processWord(byte[] in, int inOff) {
        X[xOff++] = (in[inOff] & 0xff) | ((in[inOff + 1] & 0xff) << 8)
                | ((in[inOff + 2] & 0xff) << 16) | ((in[inOff + 3] & 0xff) << 24);

        if (xOff == 16) {
            processBlock();
        }
    }

    public int doFinal(byte[] out, int outOff) {
        finish();
        unpackInt(H0, out, outOff);
        unpackInt(H1, out, outOff + 4);
        unpackInt(H2, out, outOff + 8);
        unpackInt(H3, out, outOff + 12);
        unpackInt(H4, out, outOff + 16);
        reset();
        return DIGEST_LENGTH;
    }

    public void reset() {
        H0 = 0x67452301;
        H1 = 0xefcdab89;
        H2 = 0x98badcfe;
        H3 = 0x10325476;
        H4 = 0xc3d2e1f0;
        xOff = 0;
        xBufOff = 0;
        byteCount = 0;
        for (int i = 0; i < X.length; i++) X[i] = 0;
    }

    private void finish() {
        long bitLength = (byteCount << 3);
        update((byte) 128);
        while (xBufOff != 0) update((byte) 0);
        if (xOff > 14) processBlock();
        X[14] = (int) (bitLength & 0xffffffff);
        X[15] = (int) (bitLength >>> 32);
        processBlock();
    }

    private void unpackInt(int v, byte[] out, int outOff) {
        out[outOff] = (byte) v;
        out[outOff + 1] = (byte) (v >>> 8);
        out[outOff + 2] = (byte) (v >>> 16);
        out[outOff + 3] = (byte) (v >>> 24);
    }

    private int RL(int x, int n) {
        return (x << n) | (x >>> (32 - n));
    }

    // F, G, H, I, J are the round functions
    private int f1(int x, int y, int z) { return x ^ y ^ z; }
    private int f2(int x, int y, int z) { return (x & y) | (~x & z); }
    private int f3(int x, int y, int z) { return (x | ~y) ^ z; }
    private int f4(int x, int y, int z) { return (x & z) | (y & ~z); }
    private int f5(int x, int y, int z) { return x ^ (y | ~z); }

    private void processBlock() {
        int a = H0, b = H1, c = H2, d = H3, e = H4;
        int aa = H0, bb = H1, cc = H2, dd = H3, ee = H4;
        int t;

        // Round 1
        a += f1(b, c, d) + X[0]; a = RL(a, 11) + e; c = RL(c, 10);
        e += f1(a, b, c) + X[1]; e = RL(e, 14) + d; b = RL(b, 10);
        d += f1(e, a, b) + X[2]; d = RL(d, 15) + c; a = RL(a, 10);
        c += f1(d, e, a) + X[3]; c = RL(c, 12) + b; e = RL(e, 10);
        b += f1(c, d, e) + X[4]; b = RL(b, 5) + a; d = RL(d, 10);
        a += f1(b, c, d) + X[5]; a = RL(a, 8) + e; c = RL(c, 10);
        e += f1(a, b, c) + X[6]; e = RL(e, 7) + d; b = RL(b, 10);
        d += f1(e, a, b) + X[7]; d = RL(d, 9) + c; a = RL(a, 10);
        c += f1(d, e, a) + X[8]; c = RL(c, 11) + b; e = RL(e, 10);
        b += f1(c, d, e) + X[9]; b = RL(b, 13) + a; d = RL(d, 10);
        a += f1(b, c, d) + X[10]; a = RL(a, 14) + e; c = RL(c, 10);
        e += f1(a, b, c) + X[11]; e = RL(e, 15) + d; b = RL(b, 10);
        d += f1(e, a, b) + X[12]; d = RL(d, 6) + c; a = RL(a, 10);
        c += f1(d, e, a) + X[13]; c = RL(c, 7) + b; e = RL(e, 10);
        b += f1(c, d, e) + X[14]; b = RL(b, 9) + a; d = RL(d, 10);
        a += f1(b, c, d) + X[15]; a = RL(a, 8) + e; c = RL(c, 10);

        // Round 2
        t = a; a = e; e = d; d = c; c = b; b = t; // parallel round swap logic needs care, standard implementation usually does two paths.
        // Wait, the standard RIPEMD-160 has two parallel lines: left and right.
        // The above was just one line. I need strictly parallel execution.
        
        // Reset to initial for the parallel path
        a = H0; b = H1; c = H2; d = H3; e = H4;
        
        // Re-implementing with clearer Left/Right separation
        int al = H0, bl = H1, cl = H2, dl = H3, el = H4;
        int ar = H0, br = H1, cr = H2, dr = H3, er = H4;

        // Left path - Round 1
        al += f1(bl, cl, dl) + X[0]; al = RL(al, 11) + el; cl = RL(cl, 10);
        el += f1(al, bl, cl) + X[1]; el = RL(el, 14) + dl; bl = RL(bl, 10);
        dl += f1(el, al, bl) + X[2]; dl = RL(dl, 15) + cl; al = RL(al, 10);
        cl += f1(dl, el, al) + X[3]; cl = RL(cl, 12) + bl; el = RL(el, 10);
        bl += f1(cl, dl, el) + X[4]; bl = RL(bl, 5) + al; dl = RL(dl, 10);
        al += f1(bl, cl, dl) + X[5]; al = RL(al, 8) + el; cl = RL(cl, 10);
        el += f1(al, bl, cl) + X[6]; el = RL(el, 7) + dl; bl = RL(bl, 10);
        dl += f1(el, al, bl) + X[7]; dl = RL(dl, 9) + cl; al = RL(al, 10);
        cl += f1(dl, el, al) + X[8]; cl = RL(cl, 11) + bl; el = RL(el, 10);
        bl += f1(cl, dl, el) + X[9]; bl = RL(bl, 13) + al; dl = RL(dl, 10);
        al += f1(bl, cl, dl) + X[10]; al = RL(al, 14) + el; cl = RL(cl, 10);
        el += f1(al, bl, cl) + X[11]; el = RL(el, 15) + dl; bl = RL(bl, 10);
        dl += f1(el, al, bl) + X[12]; dl = RL(dl, 6) + cl; al = RL(al, 10);
        cl += f1(dl, el, al) + X[13]; cl = RL(cl, 7) + bl; el = RL(el, 10);
        bl += f1(cl, dl, el) + X[14]; bl = RL(bl, 9) + al; dl = RL(dl, 10);
        al += f1(bl, cl, dl) + X[15]; al = RL(al, 8) + el; cl = RL(cl, 10);

        // Left path - Round 2
        al += f2(bl, cl, dl) + X[7] + 0x5a827999; al = RL(al, 7) + el; cl = RL(cl, 10);
        el += f2(al, bl, cl) + X[4] + 0x5a827999; el = RL(el, 6) + dl; bl = RL(bl, 10);
        dl += f2(el, al, bl) + X[13] + 0x5a827999; dl = RL(dl, 8) + cl; al = RL(al, 10);
        cl += f2(dl, el, al) + X[1] + 0x5a827999; cl = RL(cl, 13) + bl; el = RL(el, 10);
        bl += f2(cl, dl, el) + X[10] + 0x5a827999; bl = RL(bl, 11) + al; dl = RL(dl, 10);
        al += f2(bl, cl, dl) + X[6] + 0x5a827999; al = RL(al, 9) + el; cl = RL(cl, 10);
        el += f2(al, bl, cl) + X[15] + 0x5a827999; el = RL(el, 7) + dl; bl = RL(bl, 10);
        dl += f2(el, al, bl) + X[3] + 0x5a827999; dl = RL(dl, 15) + cl; al = RL(al, 10);
        cl += f2(dl, el, al) + X[12] + 0x5a827999; cl = RL(cl, 7) + bl; el = RL(el, 10);
        bl += f2(cl, dl, el) + X[0] + 0x5a827999; bl = RL(bl, 12) + al; dl = RL(dl, 10);
        al += f2(bl, cl, dl) + X[9] + 0x5a827999; al = RL(al, 15) + el; cl = RL(cl, 10);
        el += f2(al, bl, cl) + X[5] + 0x5a827999; el = RL(el, 9) + dl; bl = RL(bl, 10);
        dl += f2(el, al, bl) + X[2] + 0x5a827999; dl = RL(dl, 11) + cl; al = RL(al, 10);
        cl += f2(dl, el, al) + X[14] + 0x5a827999; cl = RL(cl, 7) + bl; el = RL(el, 10);
        bl += f2(cl, dl, el) + X[11] + 0x5a827999; bl = RL(bl, 13) + al; dl = RL(dl, 10);
        al += f2(bl, cl, dl) + X[8] + 0x5a827999; al = RL(al, 12) + el; cl = RL(cl, 10);

        // Left path - Round 3
        al += f3(bl, cl, dl) + X[3] + 0x6ed9eba1; al = RL(al, 11) + el; cl = RL(cl, 10);
        el += f3(al, bl, cl) + X[10] + 0x6ed9eba1; el = RL(el, 13) + dl; bl = RL(bl, 10);
        dl += f3(el, al, bl) + X[14] + 0x6ed9eba1; dl = RL(dl, 6) + cl; al = RL(al, 10);
        cl += f3(dl, el, al) + X[4] + 0x6ed9eba1; cl = RL(cl, 7) + bl; el = RL(el, 10);
        bl += f3(cl, dl, el) + X[9] + 0x6ed9eba1; bl = RL(bl, 14) + al; dl = RL(dl, 10);
        al += f3(bl, cl, dl) + X[15] + 0x6ed9eba1; al = RL(al, 9) + el; cl = RL(cl, 10);
        el += f3(al, bl, cl) + X[8] + 0x6ed9eba1; el = RL(el, 13) + dl; bl = RL(bl, 10);
        dl += f3(el, al, bl) + X[1] + 0x6ed9eba1; dl = RL(dl, 15) + cl; al = RL(al, 10);
        cl += f3(dl, el, al) + X[2] + 0x6ed9eba1; cl = RL(cl, 14) + bl; el = RL(el, 10);
        bl += f3(cl, dl, el) + X[7] + 0x6ed9eba1; bl = RL(bl, 8) + al; dl = RL(dl, 10);
        al += f3(bl, cl, dl) + X[0] + 0x6ed9eba1; al = RL(al, 13) + el; cl = RL(cl, 10);
        el += f3(al, bl, cl) + X[6] + 0x6ed9eba1; el = RL(el, 6) + dl; bl = RL(bl, 10);
        dl += f3(el, al, bl) + X[13] + 0x6ed9eba1; dl = RL(dl, 5) + cl; al = RL(al, 10);
        cl += f3(dl, el, al) + X[11] + 0x6ed9eba1; cl = RL(cl, 12) + bl; el = RL(el, 10);
        bl += f3(cl, dl, el) + X[5] + 0x6ed9eba1; bl = RL(bl, 7) + al; dl = RL(dl, 10);
        al += f3(bl, cl, dl) + X[12] + 0x6ed9eba1; al = RL(al, 5) + el; cl = RL(cl, 10);

        // Left path - Round 4
        al += f4(bl, cl, dl) + X[1] + 0x8f1bbcdc; al = RL(al, 11) + el; cl = RL(cl, 10);
        el += f4(al, bl, cl) + X[9] + 0x8f1bbcdc; el = RL(el, 12) + dl; bl = RL(bl, 10);
        dl += f4(el, al, bl) + X[11] + 0x8f1bbcdc; dl = RL(dl, 14) + cl; al = RL(al, 10);
        cl += f4(dl, el, al) + X[10] + 0x8f1bbcdc; cl = RL(cl, 15) + bl; el = RL(el, 10);
        bl += f4(cl, dl, el) + X[0] + 0x8f1bbcdc; bl = RL(bl, 14) + al; dl = RL(dl, 10);
        al += f4(bl, cl, dl) + X[8] + 0x8f1bbcdc; al = RL(al, 15) + el; cl = RL(cl, 10);
        el += f4(al, bl, cl) + X[12] + 0x8f1bbcdc; el = RL(el, 9) + dl; bl = RL(bl, 10);
        dl += f4(el, al, bl) + X[4] + 0x8f1bbcdc; dl = RL(dl, 8) + cl; al = RL(al, 10);
        cl += f4(dl, el, al) + X[13] + 0x8f1bbcdc; cl = RL(cl, 9) + bl; el = RL(el, 10);
        bl += f4(cl, dl, el) + X[3] + 0x8f1bbcdc; bl = RL(bl, 14) + al; dl = RL(dl, 10);
        al += f4(bl, cl, dl) + X[7] + 0x8f1bbcdc; al = RL(al, 5) + el; cl = RL(cl, 10);
        el += f4(al, bl, cl) + X[15] + 0x8f1bbcdc; el = RL(el, 6) + dl; bl = RL(bl, 10);
        dl += f4(el, al, bl) + X[14] + 0x8f1bbcdc; dl = RL(dl, 8) + cl; al = RL(al, 10);
        cl += f4(dl, el, al) + X[5] + 0x8f1bbcdc; cl = RL(cl, 6) + bl; el = RL(el, 10);
        bl += f4(cl, dl, el) + X[6] + 0x8f1bbcdc; bl = RL(bl, 5) + al; dl = RL(dl, 10);
        al += f4(bl, cl, dl) + X[2] + 0x8f1bbcdc; al = RL(al, 12) + el; cl = RL(cl, 10);

        // Left path - Round 5
        al += f5(bl, cl, dl) + X[4] + 0xa953fd4e; al = RL(al, 9) + el; cl = RL(cl, 10);
        el += f5(al, bl, cl) + X[0] + 0xa953fd4e; el = RL(el, 15) + dl; bl = RL(bl, 10);
        dl += f5(el, al, bl) + X[5] + 0xa953fd4e; dl = RL(dl, 5) + cl; al = RL(al, 10);
        cl += f5(dl, el, al) + X[9] + 0xa953fd4e; cl = RL(cl, 11) + bl; el = RL(el, 10);
        bl += f5(cl, dl, el) + X[7] + 0xa953fd4e; bl = RL(bl, 6) + al; dl = RL(dl, 10);
        al += f5(bl, cl, dl) + X[12] + 0xa953fd4e; al = RL(al, 8) + el; cl = RL(cl, 10);
        el += f5(al, bl, cl) + X[2] + 0xa953fd4e; el = RL(el, 13) + dl; bl = RL(bl, 10);
        dl += f5(el, al, bl) + X[10] + 0xa953fd4e; dl = RL(dl, 12) + cl; al = RL(al, 10);
        cl += f5(dl, el, al) + X[14] + 0xa953fd4e; cl = RL(cl, 5) + bl; el = RL(el, 10);
        bl += f5(cl, dl, el) + X[1] + 0xa953fd4e; bl = RL(bl, 12) + al; dl = RL(dl, 10);
        al += f5(bl, cl, dl) + X[3] + 0xa953fd4e; al = RL(al, 13) + el; cl = RL(cl, 10);
        el += f5(al, bl, cl) + X[8] + 0xa953fd4e; el = RL(el, 14) + dl; bl = RL(bl, 10);
        dl += f5(el, al, bl) + X[11] + 0xa953fd4e; dl = RL(dl, 11) + cl; al = RL(al, 10);
        cl += f5(dl, el, al) + X[6] + 0xa953fd4e; cl = RL(cl, 8) + bl; el = RL(el, 10);
        bl += f5(cl, dl, el) + X[15] + 0xa953fd4e; bl = RL(bl, 5) + al; dl = RL(dl, 10);
        al += f5(bl, cl, dl) + X[13] + 0xa953fd4e; al = RL(al, 6) + el; cl = RL(cl, 10);

        // Right path - Round 1
        ar += f5(br, cr, dr) + X[5] + 0x50a28be6; ar = RL(ar, 8) + er; cr = RL(cr, 10);
        er += f5(ar, br, cr) + X[14] + 0x50a28be6; er = RL(er, 9) + dr; br = RL(br, 10);
        dr += f5(er, ar, br) + X[7] + 0x50a28be6; dr = RL(dr, 9) + cr; ar = RL(ar, 10);
        cr += f5(dr, er, ar) + X[0] + 0x50a28be6; cr = RL(cr, 11) + br; er = RL(er, 10);
        br += f5(cr, dr, er) + X[9] + 0x50a28be6; br = RL(br, 13) + ar; dr = RL(dr, 10);
        ar += f5(br, cr, dr) + X[2] + 0x50a28be6; ar = RL(ar, 15) + er; cr = RL(cr, 10);
        er += f5(ar, br, cr) + X[11] + 0x50a28be6; er = RL(er, 15) + dr; br = RL(br, 10);
        dr += f5(er, ar, br) + X[4] + 0x50a28be6; dr = RL(dr, 5) + cr; ar = RL(ar, 10);
        cr += f5(dr, er, ar) + X[13] + 0x50a28be6; cr = RL(cr, 7) + br; er = RL(er, 10);
        br += f5(cr, dr, er) + X[6] + 0x50a28be6; br = RL(br, 7) + ar; dr = RL(dr, 10);
        ar += f5(br, cr, dr) + X[15] + 0x50a28be6; ar = RL(ar, 8) + er; cr = RL(cr, 10);
        er += f5(ar, br, cr) + X[8] + 0x50a28be6; er = RL(er, 11) + dr; br = RL(br, 10);
        dr += f5(er, ar, br) + X[1] + 0x50a28be6; dr = RL(dr, 14) + cr; ar = RL(ar, 10);
        cr += f5(dr, er, ar) + X[10] + 0x50a28be6; cr = RL(cr, 14) + br; er = RL(er, 10);
        br += f5(cr, dr, er) + X[3] + 0x50a28be6; br = RL(br, 12) + ar; dr = RL(dr, 10);
        ar += f5(br, cr, dr) + X[12] + 0x50a28be6; ar = RL(ar, 6) + er; cr = RL(cr, 10);

        // Right path - Round 2
        ar += f4(br, cr, dr) + X[6] + 0x5c4dd124; ar = RL(ar, 9) + er; cr = RL(cr, 10);
        er += f4(ar, br, cr) + X[11] + 0x5c4dd124; er = RL(er, 13) + dr; br = RL(br, 10);
        dr += f4(er, ar, br) + X[3] + 0x5c4dd124; dr = RL(dr, 15) + cr; ar = RL(ar, 10);
        cr += f4(dr, er, ar) + X[7] + 0x5c4dd124; cr = RL(cr, 7) + br; er = RL(er, 10);
        br += f4(cr, dr, er) + X[0] + 0x5c4dd124; br = RL(br, 12) + ar; dr = RL(dr, 10);
        ar += f4(br, cr, dr) + X[13] + 0x5c4dd124; ar = RL(ar, 8) + er; cr = RL(cr, 10);
        er += f4(ar, br, cr) + X[5] + 0x5c4dd124; er = RL(er, 9) + dr; br = RL(br, 10);
        dr += f4(er, ar, br) + X[10] + 0x5c4dd124; dr = RL(dr, 11) + cr; ar = RL(ar, 10);
        cr += f4(dr, er, ar) + X[14] + 0x5c4dd124; cr = RL(cr, 7) + br; er = RL(er, 10);
        br += f4(cr, dr, er) + X[15] + 0x5c4dd124; br = RL(br, 7) + ar; dr = RL(dr, 10);
        ar += f4(br, cr, dr) + X[8] + 0x5c4dd124; ar = RL(ar, 12) + er; cr = RL(cr, 10);
        er += f4(ar, br, cr) + X[12] + 0x5c4dd124; er = RL(er, 7) + dr; br = RL(br, 10);
        dr += f4(er, ar, br) + X[4] + 0x5c4dd124; dr = RL(dr, 6) + cr; ar = RL(ar, 10);
        cr += f4(dr, er, ar) + X[9] + 0x5c4dd124; cr = RL(cr, 15) + br; er = RL(er, 10);
        br += f4(cr, dr, er) + X[1] + 0x5c4dd124; br = RL(br, 13) + ar; dr = RL(dr, 10);
        ar += f4(br, cr, dr) + X[2] + 0x5c4dd124; ar = RL(ar, 11) + er; cr = RL(cr, 10);

        // Right path - Round 3
        ar += f3(br, cr, dr) + X[15] + 0x6d703ef3; ar = RL(ar, 9) + er; cr = RL(cr, 10);
        er += f3(ar, br, cr) + X[5] + 0x6d703ef3; er = RL(er, 7) + dr; br = RL(br, 10);
        dr += f3(er, ar, br) + X[1] + 0x6d703ef3; dr = RL(dr, 15) + cr; ar = RL(ar, 10);
        cr += f3(dr, er, ar) + X[3] + 0x6d703ef3; cr = RL(cr, 11) + br; er = RL(er, 10);
        br += f3(cr, dr, er) + X[7] + 0x6d703ef3; br = RL(br, 8) + ar; dr = RL(dr, 10);
        ar += f3(br, cr, dr) + X[14] + 0x6d703ef3; ar = RL(ar, 6) + er; cr = RL(cr, 10);
        er += f3(ar, br, cr) + X[6] + 0x6d703ef3; er = RL(er, 6) + dr; br = RL(br, 10);
        dr += f3(er, ar, br) + X[9] + 0x6d703ef3; dr = RL(dr, 14) + cr; ar = RL(ar, 10);
        cr += f3(dr, er, ar) + X[11] + 0x6d703ef3; cr = RL(cr, 12) + br; er = RL(er, 10);
        br += f3(cr, dr, er) + X[8] + 0x6d703ef3; br = RL(br, 13) + ar; dr = RL(dr, 10);
        ar += f3(br, cr, dr) + X[12] + 0x6d703ef3; ar = RL(ar, 5) + er; cr = RL(cr, 10);
        er += f3(ar, br, cr) + X[2] + 0x6d703ef3; er = RL(er, 14) + dr; br = RL(br, 10);
        dr += f3(er, ar, br) + X[10] + 0x6d703ef3; dr = RL(dr, 13) + cr; ar = RL(ar, 10);
        cr += f3(dr, er, ar) + X[0] + 0x6d703ef3; cr = RL(cr, 13) + br; er = RL(er, 10);
        br += f3(cr, dr, er) + X[4] + 0x6d703ef3; br = RL(br, 7) + ar; dr = RL(dr, 10);
        ar += f3(br, cr, dr) + X[13] + 0x6d703ef3; ar = RL(ar, 5) + er; cr = RL(cr, 10);

        // Right path - Round 4
        ar += f2(br, cr, dr) + X[8] + 0x7a6d76e9; ar = RL(ar, 15) + er; cr = RL(cr, 10);
        er += f2(ar, br, cr) + X[6] + 0x7a6d76e9; er = RL(er, 5) + dr; br = RL(br, 10);
        dr += f2(er, ar, br) + X[4] + 0x7a6d76e9; dr = RL(dr, 8) + cr; ar = RL(ar, 10);
        cr += f2(dr, er, ar) + X[1] + 0x7a6d76e9; cr = RL(cr, 11) + br; er = RL(er, 10);
        br += f2(cr, dr, er) + X[3] + 0x7a6d76e9; br = RL(br, 14) + ar; dr = RL(dr, 10);
        ar += f2(br, cr, dr) + X[11] + 0x7a6d76e9; ar = RL(ar, 14) + er; cr = RL(cr, 10);
        er += f2(ar, br, cr) + X[15] + 0x7a6d76e9; er = RL(er, 6) + dr; br = RL(br, 10);
        dr += f2(er, ar, br) + X[0] + 0x7a6d76e9; dr = RL(dr, 14) + cr; ar = RL(ar, 10);
        cr += f2(dr, er, ar) + X[5] + 0x7a6d76e9; cr = RL(cr, 6) + br; er = RL(er, 10);
        br += f2(cr, dr, er) + X[12] + 0x7a6d76e9; br = RL(br, 9) + ar; dr = RL(dr, 10);
        ar += f2(br, cr, dr) + X[2] + 0x7a6d76e9; ar = RL(ar, 12) + er; cr = RL(cr, 10);
        er += f2(ar, br, cr) + X[13] + 0x7a6d76e9; er = RL(er, 9) + dr; br = RL(br, 10);
        dr += f2(er, ar, br) + X[9] + 0x7a6d76e9; dr = RL(dr, 12) + cr; ar = RL(ar, 10);
        cr += f2(dr, er, ar) + X[7] + 0x7a6d76e9; cr = RL(cr, 5) + br; er = RL(er, 10);
        br += f2(cr, dr, er) + X[10] + 0x7a6d76e9; br = RL(br, 15) + ar; dr = RL(dr, 10);
        ar += f2(br, cr, dr) + X[14] + 0x7a6d76e9; ar = RL(ar, 8) + er; cr = RL(cr, 10);

        // Right path - Round 5
        ar += f1(br, cr, dr) + X[12]; ar = RL(ar, 8) + er; cr = RL(cr, 10);
        er += f1(ar, br, cr) + X[15]; er = RL(er, 5) + dr; br = RL(br, 10);
        dr += f1(er, ar, br) + X[10]; dr = RL(dr, 12) + cr; ar = RL(ar, 10);
        cr += f1(dr, er, ar) + X[4]; cr = RL(cr, 9) + br; er = RL(er, 10);
        br += f1(cr, dr, er) + X[1]; br = RL(br, 12) + ar; dr = RL(dr, 10);
        ar += f1(br, cr, dr) + X[5]; ar = RL(ar, 5) + er; cr = RL(cr, 10);
        er += f1(ar, br, cr) + X[8]; er = RL(er, 14) + dr; br = RL(br, 10);
        dr += f1(er, ar, br) + X[7]; dr = RL(dr, 6) + cr; ar = RL(ar, 10);
        cr += f1(dr, er, ar) + X[6]; cr = RL(cr, 8) + br; er = RL(er, 10);
        br += f1(cr, dr, er) + X[2]; br = RL(br, 13) + ar; dr = RL(dr, 10);
        ar += f1(br, cr, dr) + X[13]; ar = RL(ar, 6) + er; cr = RL(cr, 10);
        er += f1(ar, br, cr) + X[14]; er = RL(er, 5) + dr; br = RL(br, 10);
        dr += f1(er, ar, br) + X[0]; dr = RL(dr, 15) + cr; ar = RL(ar, 10);
        cr += f1(dr, er, ar) + X[3]; cr = RL(cr, 13) + br; er = RL(er, 10);
        br += f1(cr, dr, er) + X[9]; br = RL(br, 11) + ar; dr = RL(dr, 10);
        ar += f1(br, cr, dr) + X[11]; ar = RL(ar, 11) + er; cr = RL(cr, 10);

        // Merge
        t = H1 + cl + dr;
        H1 = H2 + dl + er;
        H2 = H3 + el + ar;
        H3 = H4 + al + br;
        H4 = H0 + bl + cr;
        H0 = t;

        xOff = 0;
        for (int i = 0; i < X.length; i++) X[i] = 0;
    }
}
