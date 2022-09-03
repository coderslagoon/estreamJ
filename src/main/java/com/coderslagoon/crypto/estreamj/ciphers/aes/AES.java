package com.coderslagoon.crypto.estreamj.ciphers.aes;

import java.util.Arrays;

/**
 * AES base class, used by both the lean(=small) and the mean(=fast) class;
 * based on the work of Brian Gladman's optimizations and C code, and the
 * Bouncy Castle translation to Java
 */
public abstract class AES {

    // packed boxes to save space (in the class file that is; let's hope the
    // class loader does things the smart way, otherwise we double the amount
    // of memory used for the boxes)
    private static final long[] S_packed = {
        0xc56f6bf27b777c63L, 0x76abd7fe2b670130L,
        0xf04759fa7dc982caL, 0xc072a49cafa2d4adL,
        0xccf73f362693fdb7L, 0x1531d871f1e5a534L,
        0x9a059618c323c704L, 0x75b227ebe2801207L,
        0xa05a6e1b1a2c8309L, 0x842fe329b3d63b52L,
        0x5bb1fc20ed00d153L, 0xcf584c4a39becb6aL,
        0x85334d43fbaaefd0L, 0xa89f3c507f02f945L,
        0xf5389d928f40a351L, 0xd2f3ff1021dab6bcL,
        0x1744975fec130ccdL, 0x73195d643d7ea7c4L,
        0x88902a22dc4f8160L, 0xdb0b5ede14b8ee46L,
        0x5c2406490a3a32e0L, 0x79e4959162acd3c2L,
        0xa94ed58d6d37c8e7L, 0x08ae7a65eaf4566cL,
        0xc6b4a61c2e2578baL, 0x8a8bbd4b1f74dde8L,
        0x0ef6034866b53e70L, 0x9e1dc186b9573561L,
        0x948ed9691198f8e1L, 0xdf2855cee9871e9bL,
        0x6842e6bf0d89a18cL, 0x16bb54b00f2d9941L
    };

    private static final long[] Si_packed = {
        0x38a53630d56a0952L, 0xfbd7f3819ea340bfL,
        0x87ff2f9b8239e37cL, 0xcbe9dec444438e34L,
        0x3d23c2a632947b54L, 0x4ec3fa420b954ceeL,
        0xb224d92866a12e08L, 0x25d18b6d49a25b76L,
        0x1698688664f6f872L, 0x92b6655dcc5ca4d4L,
        0xdab9edfd5048706cL, 0x849d8da75746155eL,
        0x0ad3bc8c00abd890L, 0x0645b3b80558e4f7L,
        0x020f3fca8f1e2cd0L, 0x6b8a130103bdafc1L,
        0xeadc674f4111913aL, 0x73e6b4f0cecff297L,
        0x8535ade72274ac96L, 0x6edf751ce837f9e2L,
        0x89c5291d711af147L, 0x1bbe18aa0e62b76fL,
        0x2079d2c64b3e56fcL, 0xf45acd78fec0db9aL,
        0x31c7078833a8dd1fL, 0x5fec8027591012b1L,
        0x0d4ab519a97f5160L, 0xef9cc9939f7ae52dL,
        0xb0f52aae4d3be0a0L, 0x619953833cbbebc8L,
        0x26d677ba7e042b17L, 0x7d0c2155631469e1L
    };

    static byte[] longsToBytes(long[] l) {
        int len = l.length;
        byte[] result = new byte[len << 3];
        for (int i = 0, pos = 0; i < len; i++) {
            long val = l[i];
            for (int j = 0; j < 8; j++) {
                result[pos++] = (byte)val;
                val >>>= 8;
            }
        }
        return result;
    }

    // unpack at startup (NOTE: if it's getting really tight memory-wise _and_
    // a garbage collector is available then we could unpack them on every
    // instance being created - and let the memory be released afterwards)
    protected static byte[] S = longsToBytes(S_packed);
    protected static byte[] Si = longsToBytes(Si_packed);

    // packing doesn't help here
    protected static final int[] rcon = {
         0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
         0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
         0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91
    };

    ///////////////////////////////////////////////////////////////////////////

    // TODO: manually inline the shift(), even if it costs us a couple of extra
    //       bytes below; the call plus the subtraction are too heavy, unless
    //       optimized away by the JIT, which I doubt; note that the shift value
    //       is always static anyway
    protected static final int shift(
            int r,
            int shift) {
        return ((r >>> shift) | (r << (32 - shift)));
    }

    protected static final int m1 = 0x80808080;
    protected static final int m2 = 0x7f7f7f7f;
    protected static final int m3 = 0x0000001b;

    protected static final int FFmulX(int x) {
        return (((x & m2) << 1) ^ (((x & m1) >>> 7) * m3));
    }

    protected static final int mcol(int x) {
        int f2 = FFmulX(x);
        return f2 ^ shift(x ^ f2, 8) ^ shift(x, 16) ^ shift(x, 24);
    }

    protected static final int inv_mcol(int x) {
        int f2 = FFmulX(x);
        int f4 = FFmulX(f2);
        int f8 = FFmulX(f4);
        int f9 = x ^ f8;

        return f2 ^ f4 ^ f8 ^ shift(f2 ^ f9, 8) ^
                              shift(f4 ^ f9, 16) ^
                              shift(f9, 24);
    }

    protected static final int subWord(int x) {
        return (S[ x         & 255] & 255         |
              ((S[(x >>>  8) & 255] & 255) <<  8) |
              ((S[(x >>> 16) & 255] & 255) << 16) |
                S[ x >>> 24       ]        << 24);  // !optimized
    }

    ///////////////////////////////////////////////////////////////////////////

    protected int ROUNDS;
    protected int[][] workingKey;
    protected int C0, C1, C2, C3;
    protected boolean forEncryption;

    public static final int BLOCK_SIZE = 16;

    public void erase() {
        for (int[] wk: this.workingKey)
            Arrays.fill(wk, 0);
        this.C0 = this.C1 = this.C2 = this.C3 = 0;
    }

    ///////////////////////////////////////////////////////////////////////////

    protected int[][] generateWorkingKey(
            byte[] key,
            int ofs,
            int len,
            boolean forEncryption) {
        int KC = len >> 2;
        int t;

        this.ROUNDS = KC + 6;
        int[][] W = new int[this.ROUNDS + 1][4];

        t = 0;
        int i = ofs;
        len += ofs;
        while (i < len) {
            W[t >> 2][t & 3] =  (key[i    ] & 0xff)        |
                               ((key[i + 1] & 0xff) <<  8) |
                               ((key[i + 2] & 0xff) << 16) |
                               ( key[i + 3]         << 24);
            i+=4;
            t++;
        }

        int k = (this.ROUNDS + 1) << 2;
        for (i = KC; (i < k); i++) {
            int temp = W[(i - 1) >> 2][(i - 1) & 3];
            if ((i % KC) == 0) {
                temp = subWord(shift(temp, 8)) ^ rcon[(i / KC) - 1];
            }
            else if ((KC > 6) && ((i % KC) == 4)) {
                temp = subWord(temp);
            }

            W[i >> 2][i & 3] = W[(i - KC) >> 2][(i - KC) & 3] ^ temp;
        }

        if (!forEncryption) {
            for (int j = 1; j < this.ROUNDS; j++) {
                for (i = 0; i < 4; i++) {
                    W[j][i] = inv_mcol(W[j][i]);
                }
            }
        }

        return W;
    }

    ///////////////////////////////////////////////////////////////////////////

    public void init(
        boolean forEncryption,
        byte[] key,
        int ofs,
        int len) {
        this.workingKey = generateWorkingKey(key, ofs, len, forEncryption);
        this.forEncryption = forEncryption;
    }

    public int processBlock(
        byte[] in,
        int inOff,
        byte[] out,
        int outOff) {
        if (this.forEncryption) {
            unpackBlock(in, inOff);
            encryptBlock(this.workingKey);
            packBlock(out, outOff);
        }
        else {
            unpackBlock(in, inOff);
            decryptBlock(this.workingKey);
            packBlock(out, outOff);
        }

        return BLOCK_SIZE;
    }

    static final int unpack(byte[] bytes, int index) {
        return ( bytes[index    ] & 0xff       ) |
               ((bytes[index + 1] & 0xff) <<  8) |
               ((bytes[index + 2] & 0xff) << 16) |
                (bytes[index + 3]         << 24);
    }

    private final void unpackBlock(
            byte[] bytes,
            int off) {
        this.C0 = unpack(bytes, off);
        this.C1 = unpack(bytes, off + 4);
        this.C2 = unpack(bytes, off + 8);
        this.C3 = unpack(bytes, off + 12);
    }

    private static void pack(int val, byte[] bytes, int index) {
        bytes[index    ] = (byte) val;
        bytes[index + 1] = (byte)(val >>> 8);
        bytes[index + 2] = (byte)(val >>> 16);
        bytes[index + 3] = (byte)(val >>> 24);
    }

    private final void packBlock(
        byte[] bytes,
        int off) {
        pack(this.C0, bytes, off);
        pack(this.C1, bytes, off + 4);
        pack(this.C2, bytes, off + 8);
        pack(this.C3, bytes, off + 12);
    }

    ///////////////////////////////////////////////////////////////////////////

    protected abstract void encryptBlock(int[][] KW);
    protected abstract void decryptBlock(int[][] KW);
}
