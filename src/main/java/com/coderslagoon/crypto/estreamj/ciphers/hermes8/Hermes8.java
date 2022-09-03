package com.coderslagoon.crypto.estreamj.ciphers.hermes8;

import java.util.Arrays;

import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.Engine;
import com.coderslagoon.crypto.estreamj.framework.ICipher;
import com.coderslagoon.crypto.estreamj.framework.ICipherMaker;

/*
 * TODO: I'm not 100% sure, but the current implementation might be restricted
 *       to ~5.7GB of data max (calculation: 3 rounds for 8 bytes, highest
 *       round number is 2^31-1); review and fix if possible...
 */

public class Hermes8 implements ICipher {
    static final int K_LENGTH = 32;
    static final int S_LENGTH = 37;
    static final int P_LENGTH = 8;
    static final int MY_INIT_ROUNDS = 10;
    static final int STREAM_ROUNDS = 3;

    static final int KEY_STEP1 = 3;
    static final int KEY_STEP2 = 5;
    static final int KEY_STEP3 = 7;

    // changed byte[] to int[] to speed things up (might be too much for small
    // devices, yet Java will still convert from bytes to integers during the
    // actual processing)
    int[] k = new int[K_LENGTH];
    int[] state = new int[S_LENGTH];
    int[] parm = new int[P_LENGTH];

    public void erase() {
        Arrays.fill(this.k, 0);
        Arrays.fill(this.state, 0);
        Arrays.fill(this.parm, 0);
    }

    // same for the S-box (assumption: nice 32bit alignment should also work
    // well if the native code is compiled in a speedy fashion
    static final int[] SBOX = {
         99,124,119,123,242,107,111,197, 48,  1,103, 43,254,215,171,118,
        202,130,201,125,250, 89, 71,240,173,212,162,175,156,164,114,192,
        183,253,147, 38, 54, 63,247,204, 52,165,229,241,113,216, 49, 21,
          4,199, 35,195, 24,150,  5,154,  7, 18,128,226,235, 39,178,117,
          9,131, 44, 26, 27,110, 90,160, 82, 59,214,179, 41,227, 47,132,
         83,209,  0,237, 32,252,177, 91,106,203,190, 57, 74, 76, 88,207,
        208,239,170,251, 67, 77, 51,133, 69,249,  2,127, 80, 60,159,168,
         81,163, 64,143,146,157, 56,245,188,182,218, 33, 16,255,243,210,
        205, 12, 19,236, 95,151, 68, 23,196,167,126, 61,100, 93, 25,115,
         96,129, 79,220, 34, 42,144,136, 70,238,184, 20,222, 94, 11,219,
        224, 50, 58, 10, 73,  6, 36, 92,194,211,172, 98,145,149,228,121,
        231,200, 55,109,141,213, 78,169,108, 86,244,234,101,122,174,  8,
        186,120, 37, 46, 28,166,180,198,232,221,116, 31, 75,189,139,138,
        112, 62,181,102, 72,  3,246, 14, 97, 53, 87,185,134,193, 29,158,
        225,248,152, 17,105,217,142,148,155, 30,135,233,206, 85, 40,223,
        140,161,137, 13,191,230, 66,104, 65,153, 45, 15,176, 84,187, 22
    };

    ///////////////////////////////////////////////////////////////////////////

    int keySize;
    int stateBytes;
    int outputBytes;

    ///////////////////////////////////////////////////////////////////////////

    public void setNonceSize(int newNonceSize) {
        this.stateBytes = newNonceSize;
    }

    ///////////////////////////////////////////////////////////////////////////

    public Hermes8(boolean use128bit) {
        if (use128bit) {
            this.keySize = 16;
            this.stateBytes = 37;
            this.outputBytes = 16;
        }
        else {
            this.keySize = 10;
            this.stateBytes = 23;
            this.outputBytes = 8;
        }
    }

    public int getKeySize() {
        return this.keySize;
    }

    public int getNonceSize() {
        return this.stateBytes;
    }

    public int getWordSize() {
        return this.outputBytes;
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
        int round;
        int nx;
        int nk;
        int p1;
        int p2;
        int src;
        int accu;
        int po;
        int p3, p4;
        int m, n;
        int j, rest, count;
        int maxloops;

        int outputBytes = this.outputBytes;
        int[] state = this.state;
        int[] k = this.k;
        int[] parm = this.parm;

        accu  = parm[0] & 0x00ff;
        p1    = parm[1];
        p2    = parm[2];
        src   = parm[3];
        round = parm[4];
        nk    = parm[5];
        nx    = parm[6];

        maxloops = len / outputBytes;
        rest = len % outputBytes;
        if (0 != rest) maxloops++;
        else rest = outputBytes;

        for (n = 1; n <= maxloops; n++) {
            for (m = 1; m <= STREAM_ROUNDS; m++) {
                round++;

                ////BEGIN_INLINED_CORE
                for (j = 1; j <= nx; j++) {
                    accu ^= state[p1] ^ k[p2];
                    accu = SBOX[accu];
                    state[p1] = accu;

                    // although it seems that
                    //
                    // p1 = (p1 + 1) % nx;
                    //
                    // might be a better alternative it is not - modulo division
                    // is heavy and will get executed in every cycle, while
                    // branch predicition reduces the cost apparently to almost
                    // nothing (100% faster, believe it or not)
                    if (++p1 >= nx) p1 = 0;

                    p2 += KEY_STEP1;
                    if (p2 >= nk) p2 = p2 - nk;

                    if (++src >= KEY_STEP3) {
                        src = src - KEY_STEP3;
                        p3 = p2 + 1; if (p3 >= nk) p3 -= nk;
                        p4 = p3 + 1; if (p4 >= nk) p4 -= nk;

                        k[p3] = SBOX[k[p3] ^ k[p2]];
                        k[p4] = SBOX[k[p4] ^ k[p2]];
                    }
                }

                if (round % KEY_STEP2 == 0 && ++p2 >= nk) {
                    p2 -= nk;
                }
                ////END_INLINED_CORE
            }

            po = p1;
            count = (n == maxloops) ? rest : outputBytes;
            for (j = 0; j < count; j++) {
                outBuf[outOfs++] = (byte)(inBuf[inOfs++] ^ state[po]);
                po += 2;
                if (po >= nx) po = po - nx;
            }
        }

        // allow continuation and store back what's necessary
        parm[0] = accu;
        parm[1] = p1;
        parm[2] = p2;
        parm[3] = src;
        parm[4] = round;
    }

    public void reset() throws ESJException {
        // nothing to do: parm[5], parm[6] and k won't get altered at all
    }

    public void setupKey(
            int mode,
            byte[] key,
            int ofs) throws ESJException {
        int[] k = this.k;
        int end = ofs + getKeySize();
        int i = 0;
        while (ofs < end) {
            k[i++] = key[ofs++] & 0x0ff;
        }
        this.parm[5] = getKeySize();
        this.parm[6] = getNonceSize();
    }

    public void setupNonce(byte[] nonce, int ofs) throws ESJException {
        // all locals changed to int (faster)
        int ivb;
        int round;
        int nk;
        int nx;
        int p1;
        int p2;
        int accu;
        int src;
        int j;
        int p3, p4;
        int[] parm = this.parm;
        int[] state = this.state;
        int[] k = this.k;


        ivb = parm[6];
        for (j = 0; j < ivb; j++ ) {
            state[j] = nonce[ofs++] & 0x0ff;
        }

        nk = parm[5];
        nx = parm[6];

        p1   = (k[0] ^ k[1] ^ k[2]) % nx;
        p2   = (k[3] ^ k[4] ^ k[5]) % nk;
        accu =  k[6] ^ k[7] ^ k[8];
        src  = (k[9] ^ k[0] ^ k[3]) % 7;


        for (round = 1; round <= MY_INIT_ROUNDS; round++) {
            ////BEGIN_INLINED_CORE
            for (j = 1; j <= nx; j++) {
                accu ^= state[p1] ^ k[p2];
                accu = SBOX[accu];
                state[p1] = accu;

                if (++p1 >= nx) p1 = 0;

                p2 += KEY_STEP1;
                if (p2 >= nk) p2 = p2 - nk;

                if (++src >= KEY_STEP3) {
                    src = src - KEY_STEP3;
                    p3 = p2 + 1; if (p3 >= nk) p3 -= nk;
                    p4 = p3 + 1; if (p4 >= nk) p4 -= nk;

                    k[p3] = SBOX[k[p3] ^ k[p2]];
                    k[p4] = SBOX[k[p4] ^ k[p2]];
                }
            }

            if (round % KEY_STEP2 == 0 && ++p2 >= nk) {
                p2 -= nk;
            }
            ////END_INLINED_CORE
        }

        parm[0] = accu;
        parm[1] = p1;
        parm[2] = p2;
        parm[3] = src;
        parm[4] = MY_INIT_ROUNDS;
    }

    ///////////////////////////////////////////////////////////////////////////

    static class Maker implements ICipherMaker {
        boolean use128bit;

        public Maker(boolean use128bit) {
            this.use128bit = use128bit;
        }

        public ICipher create() throws ESJException {
            return new Hermes8(this.use128bit);
        }

        public String getName() {
            return this.use128bit ? "Hermes8-128" : "Hermes8-80";
        }
    }

    public static void register() {
        Engine.registerCipher(new Maker(true));
        Engine.registerCipher(new Maker(false));
    }
}
