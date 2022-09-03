package com.coderslagoon.crypto.estreamj.ciphers.phelix;

import java.util.Arrays;

import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.Engine;
import com.coderslagoon.crypto.estreamj.framework.ICipher;
import com.coderslagoon.crypto.estreamj.framework.ICipherMaker;

/**
 * The Phelix implementation, based on the original PhelixJ package by
 * CODERSLAGOON.
 **/
public class Phelix implements ICipher {
    public static final int PHELIX_MAC_SIZE = 128;
    public static final int PHELIX_MAC_SIZE_96 = 96;

    private static final int PHELIX_NONCE_SIZE = 128;
    private static final int PHELIX_KEY_SIZE = 256;
    private static final int PHELIX_DATA_ALIGN = 4;

    static final int OLD_Z_REG = 4;
    static final int ZERO_INIT_CNT = 8;
    static final int MAC_INIT_CNT = 8;
    static final int MAC_WORD_CNT = PHELIX_MAC_SIZE / 32;

    static final int ROT_0a = 9;
    static final int ROT_1a = 10;
    static final int ROT_2a = 17;
    static final int ROT_3a = 30;
    static final int ROT_4a = 13;

    static final int ROT_0b = 20;
    static final int ROT_1b = 11;
    static final int ROT_2b = 5;
    static final int ROT_3b = 15;
    static final int ROT_4b = 25;

    static final int MAC_MAGIC_XOR = 0x912d94f1;
    static final int AAD_MAGIC_XOR = 0xaadaadaa;

    static final int[] MASK_LEFTOVER = { 0, 0x00ff, 0x00ffff, 0x00ffffff };

    int ks_keySize;
    int ks_macSize;
    int ks_X_1_bump;
    int[] ks_X_0 = new int[8];
    int[] ks_X_1 = new int[8];

    int[] cs_oldZ = new int[4];
    int[] cs_Z = new int[5];
    int cs_i;
    long cs_aadLen;
    long cs_msgLen;
    int cs_aadXor;

    int[] cache_finalize_tmp = new int[MAC_INIT_CNT + MAC_WORD_CNT];
    int[] cache_processbytes_buckets = new int[2];
    int bucketIdx;

    public void erase() {
        Arrays.fill(this.ks_X_0, 0);
        Arrays.fill(this.ks_X_1, 0);
        Arrays.fill(this.cs_oldZ, 0);
        Arrays.fill(this.cs_Z, 0);
        Arrays.fill(this.cache_finalize_tmp, 0);
        Arrays.fill(this.cache_processbytes_buckets, 0);
    }

    public Phelix(int macSize) {
        this.ks_macSize = macSize;
        reset();
    }

    public void reset() {
        this.cs_i = 0;
        this.cs_msgLen = 0;
    }

    public void setupKey(
        int mode,
        byte[] key,
        int keyOfs) throws ESJException {
        setupKeyEx(mode, key, keyOfs, getKeySize() << 3);
    }

    public void setupKeyEx(
        int mode,
        byte[] key,
        int keyOfs,
        int keySize) throws ESJException {
        int i, k, rep, tmp;
        int Z_0, Z_1, Z_2, Z_3, Z_4;

        this.bucketIdx = ICipher.MODE_ENCRYPT == mode ? 0 : 1;

        int[] X = this.ks_X_0;

        if (PHELIX_KEY_SIZE < keySize || keySize < 0) {
            throw new ESJException("invalid key size" + keySize);
        }

        if (0 != (keySize & 7)) {
            throw new ESJException("key must be byte-sized");
        }

        this.ks_keySize = keySize;

        this.ks_X_1_bump = (keySize >>> 1) +
                           ((this.ks_macSize % PHELIX_MAC_SIZE) << 8);

        tmp = (keySize + 31) >>> 5;

        for (i = 0; i < tmp; i++) {
            X[i] =  (key[keyOfs    ] & 0x0ff)        |
                   ((key[keyOfs + 1] & 0x0ff) <<  8) |
                   ((key[keyOfs + 2] & 0x0ff) << 16) |
                   ((key[keyOfs + 3] & 0x0ff) << 24);
            keyOfs += 4;
        }

        for (; i < 8; i++) {
            X[i] = 0;
        }

        if (0 != (0x1f & keySize)) {
            X[keySize >>> 5] &= ((keySize & 0x1f) << 1) - 1;
        }

        tmp = (keySize >>> 3) + 64;

        for (i = 0; i < 8; i++) {
            k = (i & 1) << 2;

            Z_0 = X[k];
            Z_1 = X[k + 1];
            Z_2 = X[k + 2];
            Z_3 = X[k + 3];
            Z_4 = tmp;

            for (rep = 0; rep < 2; rep++) {
                Z_0 += Z_3; Z_3 = (Z_3 << ROT_3b) | (Z_3 >>> (32 - ROT_3b));
                Z_1 += Z_4; Z_4 = (Z_4 << ROT_4b) | (Z_4 >>> (32 - ROT_4b));
                Z_2 ^= Z_0; Z_0 = (Z_0 << ROT_0a) | (Z_0 >>> (32 - ROT_0a));
                Z_3 ^= Z_1; Z_1 = (Z_1 << ROT_1a) | (Z_1 >>> (32 - ROT_1a));
                Z_4 += Z_2; Z_2 = (Z_2 << ROT_2a) | (Z_2 >>> (32 - ROT_2a));

                Z_0 ^= Z_3; Z_3 = (Z_3 << ROT_3a) | (Z_3 >>> (32 - ROT_3a));
                Z_1 ^= Z_4; Z_4 = (Z_4 << ROT_4a) | (Z_4 >>> (32 - ROT_4a));
                Z_2 += Z_0; Z_0 = (Z_0 << ROT_0b) | (Z_0 >>> (32 - ROT_0b));
                Z_3 += Z_1; Z_1 = (Z_1 << ROT_1b) | (Z_1 >>> (32 - ROT_1b));
                Z_4 ^= Z_2; Z_2 = (Z_2 << ROT_2b) | (Z_2 >>> (32 - ROT_2b));
            }

            k = (k + 4) & 7;

            X[k]     ^= Z_0;
            X[k + 1] ^= Z_1;
            X[k + 2] ^= Z_2;
            X[k + 3] ^= Z_3;
        }
    }

    public void setupNonce(
        byte[] nonce,
        int nonceOfs) {
        int i, j, n;
        int[] X_0, X_1, oldZ, Z;
        int X_1_bump;
        int Z_0, Z_1, Z_2, Z_3, Z_4;

        X_0 = this.ks_X_0;
        X_1 = this.ks_X_1;
        X_1_bump = this.ks_X_1_bump;
        Z = this.cs_Z;
        oldZ = this.cs_oldZ;

        for (i = 0; i < 4; i++, nonceOfs += 4) {
            n =  (nonce[nonceOfs    ] & 0x0ff)        |
                ((nonce[nonceOfs + 1] & 0x0ff) <<  8) |
                ((nonce[nonceOfs + 2] & 0x0ff) << 16) |
                ((nonce[nonceOfs + 3] & 0x0ff) << 24);

            X_1[i] = X_0[i + 4] + n;
            X_1[i + 4] = X_0[i] + (i - n);
            Z[i] = X_0[i + 3] ^ n;
        }

        X_1[1] += X_1_bump;
        X_1[5] += X_1_bump;
        Z[4] = X_0[7];

        this.cs_aadLen = 0L;
        this.cs_msgLen = 0L;

        Z_0 = Z[0];
        Z_1 = Z[1];
        Z_2 = Z[2];
        Z_3 = Z[3];
        Z_4 = Z[4];

        for (i = 0; i < 8; i++) {
            j = i & 7;

            Z_0 += Z_3; Z_3 = (Z_3 << ROT_3b) | (Z_3 >>> (32 - ROT_3b));
            Z_1 += Z_4; Z_4 = (Z_4 << ROT_4b) | (Z_4 >>> (32 - ROT_4b));
            Z_2 ^= Z_0; Z_0 = (Z_0 << ROT_0a) | (Z_0 >>> (32 - ROT_0a));
            Z_3 ^= Z_1; Z_1 = (Z_1 << ROT_1a) | (Z_1 >>> (32 - ROT_1a));
            Z_4 += Z_2; Z_2 = (Z_2 << ROT_2a) | (Z_2 >>> (32 - ROT_2a));

            Z_0 ^= Z_3 + X_0[j]; Z_3 = (Z_3 << ROT_3a) | (Z_3 >>> (32 - ROT_3a));
            Z_1 ^= Z_4;          Z_4 = (Z_4 << ROT_4a) | (Z_4 >>> (32 - ROT_4a));
            Z_2 += Z_0;          Z_0 = (Z_0 << ROT_0b) | (Z_0 >>> (32 - ROT_0b));
            Z_3 += Z_1;          Z_1 = (Z_1 << ROT_1b) | (Z_1 >>> (32 - ROT_1b));
            Z_4 ^= Z_2;          Z_2 = (Z_2 << ROT_2b) | (Z_2 >>> (32 - ROT_2b));

            Z_0 += Z_3; Z_3 = (Z_3 << ROT_3b) | (Z_3 >>> (32 - ROT_3b));
            Z_1 += Z_4; Z_4 = (Z_4 << ROT_4b) | (Z_4 >>> (32 - ROT_4b));
            Z_2 ^= Z_0; Z_0 = (Z_0 << ROT_0a) | (Z_0 >>> (32 - ROT_0a));
            Z_3 ^= Z_1; Z_1 = (Z_1 << ROT_1a) | (Z_1 >>> (32 - ROT_1a));
            Z_4 += Z_2; Z_2 = (Z_2 << ROT_2a) | (Z_2 >>> (32 - ROT_2a));

            Z_0 ^= Z_3 + X_1[j] + i; Z_3 = (Z_3 << ROT_3a) | (Z_3 >>> (32 - ROT_3a));
            Z_1 ^= Z_4;              Z_4 = (Z_4 << ROT_4a) | (Z_4 >>> (32 - ROT_4a));
            Z_2 += Z_0;              Z_0 = (Z_0 << ROT_0b) | (Z_0 >>> (32 - ROT_0b));
            Z_3 += Z_1;              Z_1 = (Z_1 << ROT_1b) | (Z_1 >>> (32 - ROT_1b));
            Z_4 ^= Z_2;              Z_2 = (Z_2 << ROT_2b) | (Z_2 >>> (32 - ROT_2b));

            oldZ[i & 3] = Z_4; //Z[OLD_Z_REG];
        }

        Z[0] = Z_0;
        Z[1] = Z_1;
        Z[2] = Z_2;
        Z[3] = Z_3;
        Z[4] = Z_4;

        Z[1] ^= (this.cs_aadXor = AAD_MAGIC_XOR);

        this.cs_i = i;
    }

    public void process(
        byte[] inBuf,
        int inbufOfs,
        byte[] outBuf,
        int outbufOfs,
        int msgLen) throws ESJException {
        int leftOver, endOfs, c, bidx;
        int i, j, ptxt, tmp;
        int[] buckets = this.cache_processbytes_buckets;
        int[] X_0, X_1, oldZ, Z;
        int Z_0, Z_1, Z_2, Z_3, Z_4;

        bidx = this.bucketIdx;
        X_0 = this.ks_X_0;
        X_1 = this.ks_X_1;
        Z = this.cs_Z;
        oldZ = this.cs_oldZ;

        if (0 != (3 & this.cs_msgLen)) {
            throw new ESJException("data misalignment, only the last data" +
                    " junk can be off a " + PHELIX_DATA_ALIGN +
                    "{0}-byte border");
        }

        this.cs_msgLen += msgLen & 0x0ffffffffL;
        i = this.cs_i;
        this.cs_Z[1] ^= this.cs_aadXor;
        this.cs_aadXor = 0;

        Z_0 = Z[0];
        Z_1 = Z[1];
        Z_2 = Z[2];
        Z_3 = Z[3];
        Z_4 = Z[4];

        leftOver = msgLen & 3;
        endOfs = inbufOfs + (msgLen - leftOver);

        for (; inbufOfs < endOfs; i++, inbufOfs += 4, outbufOfs += 4) {
            j = i & 7;

            Z_0 += Z_3; Z_3 = (Z_3 << ROT_3b) | (Z_3 >>> (32 - ROT_3b));
            Z_1 += Z_4; Z_4 = (Z_4 << ROT_4b) | (Z_4 >>> (32 - ROT_4b));
            Z_2 ^= Z_0; Z_0 = (Z_0 << ROT_0a) | (Z_0 >>> (32 - ROT_0a));
            Z_3 ^= Z_1; Z_1 = (Z_1 << ROT_1a) | (Z_1 >>> (32 - ROT_1a));
            Z_4 += Z_2; Z_2 = (Z_2 << ROT_2a) | (Z_2 >>> (32 - ROT_2a));

            Z_0 ^= Z_3 + X_0[j]; Z_3 = (Z_3 << ROT_3a) | (Z_3 >>> (32 - ROT_3a));
            Z_1 ^= Z_4;          Z_4 = (Z_4 << ROT_4a) | (Z_4 >>> (32 - ROT_4a));
            Z_2 += Z_0;          Z_0 = (Z_0 << ROT_0b) | (Z_0 >>> (32 - ROT_0b));
            Z_3 += Z_1;          Z_1 = (Z_1 << ROT_1b) | (Z_1 >>> (32 - ROT_1b));
            Z_4 ^= Z_2;          Z_2 = (Z_2 << ROT_2b) | (Z_2 >>> (32 - ROT_2b));

            buckets[0] = tmp = (inBuf[inbufOfs    ] & 0x0ff)        |
                              ((inBuf[inbufOfs + 1] & 0x0ff) <<  8) |
                              ((inBuf[inbufOfs + 2] & 0x0ff) << 16) |
                              ((inBuf[inbufOfs + 3] & 0x0ff) << 24);

            tmp ^= Z_4 + oldZ[i & 3];

            outBuf[outbufOfs]     = (byte) tmp;
            outBuf[outbufOfs + 1] = (byte)(tmp >>>  8);
            outBuf[outbufOfs + 2] = (byte)(tmp >>> 16);
            outBuf[outbufOfs + 3] = (byte)(tmp >>> 24);

            buckets[1] = tmp;

            Z_0 += Z_3 ^ buckets[bidx]; Z_3 = (Z_3 << ROT_3b) | (Z_3 >>> (32 - ROT_3b));
            Z_1 += Z_4;                 Z_4 = (Z_4 << ROT_4b) | (Z_4 >>> (32 - ROT_4b));
            Z_2 ^= Z_0;                 Z_0 = (Z_0 << ROT_0a) | (Z_0 >>> (32 - ROT_0a));
            Z_3 ^= Z_1;                 Z_1 = (Z_1 << ROT_1a) | (Z_1 >>> (32 - ROT_1a));
            Z_4 += Z_2;                 Z_2 = (Z_2 << ROT_2a) | (Z_2 >>> (32 - ROT_2a));

            Z_0 ^= Z_3 + X_1[j] + i; Z_3 = (Z_3 << ROT_3a) | (Z_3 >>> (32 - ROT_3a));
            Z_1 ^= Z_4;              Z_4 = (Z_4 << ROT_4a) | (Z_4 >>> (32 - ROT_4a));
            Z_2 += Z_0;              Z_0 = (Z_0 << ROT_0b) | (Z_0 >>> (32 - ROT_0b));
            Z_3 += Z_1;              Z_1 = (Z_1 << ROT_1b) | (Z_1 >>> (32 - ROT_1b));
            Z_4 ^= Z_2;              Z_2 = (Z_2 << ROT_2b) | (Z_2 >>> (32 - ROT_2b));

            oldZ[i & 3] = Z_4; //Z[OLD_Z_REG];
        }

        if (0 != leftOver) {
            j = i & 7;

            Z_0 += Z_3; Z_3 = (Z_3 << ROT_3b) | (Z_3 >>> (32 - ROT_3b));
            Z_1 += Z_4; Z_4 = (Z_4 << ROT_4b) | (Z_4 >>> (32 - ROT_4b));
            Z_2 ^= Z_0; Z_0 = (Z_0 << ROT_0a) | (Z_0 >>> (32 - ROT_0a));
            Z_3 ^= Z_1; Z_1 = (Z_1 << ROT_1a) | (Z_1 >>> (32 - ROT_1a));
            Z_4 += Z_2; Z_2 = (Z_2 << ROT_2a) | (Z_2 >>> (32 - ROT_2a));

            Z_0 ^= Z_3 + X_0[j]; Z_3 = (Z_3 << ROT_3a) | (Z_3 >>> (32 - ROT_3a));
            Z_1 ^= Z_4;          Z_4 = (Z_4 << ROT_4a) | (Z_4 >>> (32 - ROT_4a));
            Z_2 += Z_0;          Z_0 = (Z_0 << ROT_0b) | (Z_0 >>> (32 - ROT_0b));
            Z_3 += Z_1;          Z_1 = (Z_1 << ROT_1b) | (Z_1 >>> (32 - ROT_1b));
            Z_4 ^= Z_2;          Z_2 = (Z_2 << ROT_2b) | (Z_2 >>> (32 - ROT_2b));

            ptxt = 0;   // (jtptc)
            tmp = leftOver << 3;
            for (c = 0; c < tmp; c += 8) {
                ptxt |= (inBuf[inbufOfs++] & 0x0ff) << c;
            }

            buckets[0] = tmp = ptxt;

            tmp ^= Z_4 + oldZ[i & 3];

            buckets[1] = tmp & MASK_LEFTOVER[leftOver];

            for (c = 0; c < leftOver; c++, tmp >>>= 8, outbufOfs++) {
                outBuf[outbufOfs] = (byte)tmp;
            }

            Z_0 += Z_3 ^ buckets[bidx]; Z_3 = (Z_3 << ROT_3b) | (Z_3 >>> (32 - ROT_3b));
            Z_1 += Z_4;                 Z_4 = (Z_4 << ROT_4b) | (Z_4 >>> (32 - ROT_4b));
            Z_2 ^= Z_0;                 Z_0 = (Z_0 << ROT_0a) | (Z_0 >>> (32 - ROT_0a));
            Z_3 ^= Z_1;                 Z_1 = (Z_1 << ROT_1a) | (Z_1 >>> (32 - ROT_1a));
            Z_4 += Z_2;                 Z_2 = (Z_2 << ROT_2a) | (Z_2 >>> (32 - ROT_2a));

            Z_0 ^= Z_3 + X_1[j] + i; Z_3 = (Z_3 << ROT_3a) | (Z_3 >>> (32 - ROT_3a));
            Z_1 ^= Z_4;              Z_4 = (Z_4 << ROT_4a) | (Z_4 >>> (32 - ROT_4a));
            Z_2 += Z_0;              Z_0 = (Z_0 << ROT_0b) | (Z_0 >>> (32 - ROT_0b));
            Z_3 += Z_1;              Z_1 = (Z_1 << ROT_1b) | (Z_1 >>> (32 - ROT_1b));
            Z_4 ^= Z_2;              Z_2 = (Z_2 << ROT_2b) | (Z_2 >>> (32 - ROT_2b));

            oldZ[i & 3] = Z_4;

            i++;
        }

        Z[0] = Z_0;
        Z[1] = Z_1;
        Z[2] = Z_2;
        Z[3] = Z_3;
        Z[4] = Z_4;

        this.cs_i = i;
    }

    public void processAAD(
        byte[] aad,
        int aadOfs,
        int aadLen) throws ESJException {
        int c;
        int i, j, ptxt;
        int[] X_0, X_1, oldZ, Z;
        int Z_0, Z_1, Z_2, Z_3, Z_4;


        X_0 = this.ks_X_0;
        X_1 = this.ks_X_1;
        Z = this.cs_Z;
        oldZ = this.cs_oldZ;

        if (0 != (3 & this.cs_aadLen)) {
            throw new ESJException("data misalignment for AAD, only the " +
                "last data junk can be off a " + PHELIX_DATA_ALIGN +
                "-byte border");
        }

        this.cs_aadLen += aadLen & 0x0ffffffffL;
        i = this.cs_i;

        Z_0 = Z[0];
        Z_1 = Z[1];
        Z_2 = Z[2];
        Z_3 = Z[3];
        Z_4 = Z[4];

        for (; 0 < aadLen; i++, aadOfs += 4) {
            j = i & 7;

            Z_0 += Z_3; Z_3 = (Z_3 << ROT_3b) | (Z_3 >>> (32 - ROT_3b));
            Z_1 += Z_4; Z_4 = (Z_4 << ROT_4b) | (Z_4 >>> (32 - ROT_4b));
            Z_2 ^= Z_0; Z_0 = (Z_0 << ROT_0a) | (Z_0 >>> (32 - ROT_0a));
            Z_3 ^= Z_1; Z_1 = (Z_1 << ROT_1a) | (Z_1 >>> (32 - ROT_1a));
            Z_4 += Z_2; Z_2 = (Z_2 << ROT_2a) | (Z_2 >>> (32 - ROT_2a));

            Z_0 ^= Z_3 + X_0[j]; Z_3 = (Z_3 << ROT_3a) | (Z_3 >>> (32 - ROT_3a));
            Z_1 ^= Z_4;          Z_4 = (Z_4 << ROT_4a) | (Z_4 >>> (32 - ROT_4a));
            Z_2 += Z_0;          Z_0 = (Z_0 << ROT_0b) | (Z_0 >>> (32 - ROT_0b));
            Z_3 += Z_1;          Z_1 = (Z_1 << ROT_1b) | (Z_1 >>> (32 - ROT_1b));
            Z_4 ^= Z_2;          Z_2 = (Z_2 << ROT_2b) | (Z_2 >>> (32 - ROT_2b));

            if (4 <= aadLen) {
                ptxt = (aad[aadOfs    ] & 0x0ff)        |
                      ((aad[aadOfs + 1] & 0x0ff) <<  8) |
                      ((aad[aadOfs + 2] & 0x0ff) << 16) |
                      ((aad[aadOfs + 3] & 0x0ff) << 24);
                aadLen -= 4;
            }
            else {
                ptxt = 0;   // (jtptc)

                aadLen <<= 3;
                for (c = 0; c < aadLen; c += 8) {
                    ptxt |= (aad[aadOfs++] & 0x0ff) << c;
                }
                aadLen = 0;
            }

            Z_0 += Z_3 ^ ptxt; Z_3 = (Z_3 << ROT_3b) | (Z_3 >>> (32 - ROT_3b));
            Z_1 += Z_4;        Z_4 = (Z_4 << ROT_4b) | (Z_4 >>> (32 - ROT_4b));
            Z_2 ^= Z_0;        Z_0 = (Z_0 << ROT_0a) | (Z_0 >>> (32 - ROT_0a));
            Z_3 ^= Z_1;        Z_1 = (Z_1 << ROT_1a) | (Z_1 >>> (32 - ROT_1a));
            Z_4 += Z_2;        Z_2 = (Z_2 << ROT_2a) | (Z_2 >>> (32 - ROT_2a));

            Z_0 ^= Z_3 + X_1[j] + i; Z_3 = (Z_3 << ROT_3a) | (Z_3 >>> (32 - ROT_3a));
            Z_1 ^= Z_4;              Z_4 = (Z_4 << ROT_4a) | (Z_4 >>> (32 - ROT_4a));
            Z_2 += Z_0;              Z_0 = (Z_0 << ROT_0b) | (Z_0 >>> (32 - ROT_0b));
            Z_3 += Z_1;              Z_1 = (Z_1 << ROT_1b) | (Z_1 >>> (32 - ROT_1b));
            Z_4 ^= Z_2;              Z_2 = (Z_2 << ROT_2b) | (Z_2 >>> (32 - ROT_2b));

            oldZ[i & 3] = Z_4;
        }

        Z[0] = Z_0;
        Z[1] = Z_1;
        Z[2] = Z_2;
        Z[3] = Z_3;
        Z[4] = Z_4;

        this.cs_i = i;
    }

    public void finalize(
        byte[] mac,
        int macOfs) {
        int c, end;
        int i, j, k, t, ptxt;
        int[] Z, X_0, X_1, oldZ;
        int Z_0, Z_1, Z_2, Z_3, Z_4;
        int[] tmp = this.cache_finalize_tmp;


        X_0 = this.ks_X_0;
        X_1 = this.ks_X_1;
        Z = this.cs_Z;
        oldZ = this.cs_oldZ;

        i = this.cs_i;
        ptxt = (int)this.cs_msgLen & 3;

        Z_0 = Z[0];
        Z_1 = Z[1];
        Z_2 = Z[2];
        Z_3 = Z[3];
        Z_4 = Z[4];

        Z_0 ^= MAC_MAGIC_XOR;
        Z_4 ^= this.cs_aadLen;
        Z_2 ^= this.cs_aadLen >>> 32;
        Z_1 ^= this.cs_aadXor;

        for (k = 0; k < tmp.length; k++, i++) {
            j = i & 7;

            Z_0 += Z_3; Z_3 = (Z_3 << ROT_3b) | (Z_3 >>> (32 - ROT_3b));
            Z_1 += Z_4; Z_4 = (Z_4 << ROT_4b) | (Z_4 >>> (32 - ROT_4b));
            Z_2 ^= Z_0; Z_0 = (Z_0 << ROT_0a) | (Z_0 >>> (32 - ROT_0a));
            Z_3 ^= Z_1; Z_1 = (Z_1 << ROT_1a) | (Z_1 >>> (32 - ROT_1a));
            Z_4 += Z_2; Z_2 = (Z_2 << ROT_2a) | (Z_2 >>> (32 - ROT_2a));

            Z_0 ^= Z_3 + X_0[j]; Z_3 = (Z_3 << ROT_3a) | (Z_3 >>> (32 - ROT_3a));
            Z_1 ^= Z_4;          Z_4 = (Z_4 << ROT_4a) | (Z_4 >>> (32 - ROT_4a));
            Z_2 += Z_0;          Z_0 = (Z_0 << ROT_0b) | (Z_0 >>> (32 - ROT_0b));
            Z_3 += Z_1;          Z_1 = (Z_1 << ROT_1b) | (Z_1 >>> (32 - ROT_1b));
            Z_4 ^= Z_2;          Z_2 = (Z_2 << ROT_2b) | (Z_2 >>> (32 - ROT_2b));

            tmp[k] = ptxt ^ (Z_4 + oldZ[i & 3]);

            Z_0 += Z_3 ^ ptxt; Z_3 = (Z_3 << ROT_3b) | (Z_3 >>> (32 - ROT_3b));
            Z_1 += Z_4;        Z_4 = (Z_4 << ROT_4b) | (Z_4 >>> (32 - ROT_4b));
            Z_2 ^= Z_0;        Z_0 = (Z_0 << ROT_0a) | (Z_0 >>> (32 - ROT_0a));
            Z_3 ^= Z_1;        Z_1 = (Z_1 << ROT_1a) | (Z_1 >>> (32 - ROT_1a));
            Z_4 += Z_2;        Z_2 = (Z_2 << ROT_2a) | (Z_2 >>> (32 - ROT_2a));

            Z_0 ^= Z_3 + X_1[j] + i; Z_3 = (Z_3 << ROT_3a) | (Z_3 >>> (32 - ROT_3a));
            Z_1 ^= Z_4;              Z_4 = (Z_4 << ROT_4a) | (Z_4 >>> (32 - ROT_4a));
            Z_2 += Z_0;              Z_0 = (Z_0 << ROT_0b) | (Z_0 >>> (32 - ROT_0b));
            Z_3 += Z_1;              Z_1 = (Z_1 << ROT_1b) | (Z_1 >>> (32 - ROT_1b));
            Z_4 ^= Z_2;              Z_2 = (Z_2 << ROT_2b) | (Z_2 >>> (32 - ROT_2b));

            oldZ[i & 3] = Z_4;
        }

        c = end = MAC_INIT_CNT;
        end += (96 == this.ks_macSize) ? 3 : 4;

        while (c < end) {
            t = tmp[c++];
            mac[macOfs++] = (byte) t;
            mac[macOfs++] = (byte)(t >>> 8);
            mac[macOfs++] = (byte)(t >>> 16);
            mac[macOfs++] = (byte)(t >>> 24);
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    public int getKeySize() {
        return PHELIX_KEY_SIZE >> 3;
    }

    public int getMacSize() {
        return this.ks_macSize >> 3;
    }

    public int getNonceSize() {
        return PHELIX_NONCE_SIZE >> 3;
    }

    public int getWordSize() {
        return PHELIX_DATA_ALIGN;
    }

    public boolean isPatented() {
        return false;
    }

    ///////////////////////////////////////////////////////////////////////////

    static class Maker implements ICipherMaker {
        int macSize;

        public Maker(int macSize) {
            this.macSize = macSize;
        }

        public ICipher create() throws ESJException {
            return new Phelix(this.macSize);
        }

        public String getName() {
            return PHELIX_MAC_SIZE_96 == this.macSize ? "Phelix96" :  "Phelix";
        }
    }

    public static void register() {
        // register both of the Phelix variants
        Engine.registerCipher(new Maker(PHELIX_MAC_SIZE_96));
        Engine.registerCipher(new Maker(PHELIX_MAC_SIZE));
    }
}
