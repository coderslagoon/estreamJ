package com.coderslagoon.crypto.estreamj.ciphers.hc256;

import java.util.Arrays;
import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.Engine;
import com.coderslagoon.crypto.estreamj.framework.ICipher;
import com.coderslagoon.crypto.estreamj.framework.ICipherMaker;

public class HC256 implements ICipher {
    int[] P = new int[1024];
    int[] Q = new int[1024];
    int counter2048 = -1;
    int[] key = new int[8];
    int[] iv = new int[8];
    int keysize = -1;
    int ivsize = -1;

    int[] P_bak;
    int[] Q_bak;
    int counter2048_bak;

    int[] cached_setupNonce_W = new int[2560];

    public void erase() {
        Arrays.fill(this.P, 0);
        Arrays.fill(this.Q, 0);
        Arrays.fill(this.key, 0);
        Arrays.fill(this.iv, 0);
        Arrays.fill(this.P_bak, 0);
        Arrays.fill(this.Q_bak, 0);
        Arrays.fill(this.cached_setupNonce_W, 0);
    }

    ///////////////////////////////////////////////////////////////////////////

    public int getKeySize() {
        return 256 >>> 3;
    }

    public int getNonceSize() {
        return 256 >>> 3;
    }

    public int getWordSize() {
        return 4;
    }

    public boolean isPatented() {
        return false;
    }

    public void process(
            byte[] inBuf,
            int inOfs,
            byte[] outBuf,
            int outOfs,
            int len) throws ESJException {
        int i, j, msglen32, keystreamword;

        msglen32 = len >> 2;

        for (i = 0; i < msglen32; i++) {
              keystreamword = generate();

              for (j = 0; j < 4; j++) {
                  outBuf[outOfs] = (byte)(inBuf[inOfs] ^ keystreamword);
                  outOfs++;
                  inOfs++;
                  keystreamword >>= 8;
              }
        }

        keystreamword = generate();
        for (i = 0; i < (len & 3); i++) {
              outBuf[outOfs] = (byte)(inBuf[inOfs] ^ keystreamword);
              outOfs++;
              inOfs++;
              keystreamword >>= 8;
        }
    }

    public void reset() throws ESJException {
        System.arraycopy(this.P_bak, 0, this.P, 0, this.P.length);
        System.arraycopy(this.Q_bak, 0, this.Q, 0, this.Q.length);
        this.counter2048 = this.counter2048_bak;
    }

    public void setupKey(int mode, byte[] key, int ofs) throws ESJException {
        int i, j, ksz, tmp;

        int[] this_key = this.key;

        ksz = this.keysize = getKeySize();

        Arrays.fill(this.key, 0);

        for (i = 0; (i < ksz) && (i < 32); i++) {
            j = i >> 2;
            tmp = this_key[j] | (key[i + ofs] & 0x0ff);
            this_key[j] = (tmp << 8) | (tmp >>> 24);
        }
    }

    public void setupNonce(byte[] nonce, int ofs) throws ESJException {
        int i, j, tmp, x;
        int ivsize = this.ivsize = getNonceSize();
        int[] W = this.cached_setupNonce_W;
        int[] iv = this.iv;
        int[] P = this.P;
        int[] Q = this.Q;

        Arrays.fill(iv, 0);
        for (i = 0; (i < ivsize) && (i < 32); i++) {
            j = i >> 2;
            tmp = iv[j] | (nonce[i + ofs] & 0x0ff);
            iv[j] = (tmp << 8) | (tmp >>> 24);
        }

        for (i = 0; i < 8;  i++) W[i] = this.key[i];
        for (i = 8; i < 16; i++) W[i] = iv[i - 8];

        for (i = 16; i < 2560; i++) {
            x = W[i - 2];
            tmp = ((x >>> 17) | (x << 15)) ^ ((x >>> 19) | (x << 13)) ^ (x >>> 10);
            tmp += W[i - 7] + W[i - 16] + i;
            x = W[i - 15];
            tmp += ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
            W[i] = tmp;
        }

        for (i = 0; i < 1024; i++) P[i] = W[i + 512];
        for (i = 0; i < 1024; i++) Q[i] = W[i + 1536];

        this.counter2048 = 0;

        for (i = 0; i < 4096; i++) {
            generate();
        }

        this.P_bak = this.P.clone();
        this.Q_bak = this.Q.clone();
        this.counter2048_bak = this.counter2048;
    }

    private int generate() {
        int i, i3, i10, i12, i1023;
        int tmp, x, y;
        int output;
        int[] P = this.P;
        int[] Q = this.Q;

        i   = this.counter2048 & 0x3ff;
        i3  = (i - 3) & 0x3ff;
        i10 = (i - 10) & 0x3ff;
        i12 = (i - 12) & 0x3ff;
        i1023 = (i - 1023) & 0x3ff;

        if (this.counter2048 < 1024) {
            tmp = P[i] + P[i10] + Q[(P[i3] ^ P[i1023]) & 0x3ff];
            x = P[i3];
            y = P[i1023];
            tmp += ((x >>> 10) | (x << 22)) ^ ((y >>> 23) | (y << 9));
            P[i] = tmp;

            x = P[i12];
            y = Q[        x         & 0x0ff ] +
                Q[256 + ((x >>>  8) & 0x0ff)] +
                Q[512 + ((x >>> 16) & 0x0ff)] +
                Q[768 +  (x >>> 24)         ];
        }
        else {
            tmp = Q[i] + Q[i10] + P[(Q[i3] ^ Q[i1023]) & 0x3ff];
            x = Q[i3];
            y = Q[i1023];
            tmp += ((x >>> 10) | (x << 22)) ^ ((y >>> 23) | (y << 9));
            Q[i] = tmp;

            x = Q[i12];
            y = P[        x         & 0x0ff ] +
                P[256 + ((x >>>  8) & 0x0ff)] +
                P[512 + ((x >>> 16) & 0x0ff)] +
                P[768 +  (x >>> 24)         ];
        }
        output = y ^ tmp;
        this.counter2048 = (this.counter2048 + 1) & 0x7ff;
        return (output);
    }

    ///////////////////////////////////////////////////////////////////////////

    static class Maker implements ICipherMaker {
        public ICipher create() throws ESJException {
            return new HC256();
        }

        public String getName() {
            return "HC-256";
        }
    }

    public static void register() {
        Engine.registerCipher(new Maker());
    }
}
