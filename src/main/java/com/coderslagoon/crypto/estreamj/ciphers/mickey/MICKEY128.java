package com.coderslagoon.crypto.estreamj.ciphers.mickey;

import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.Engine;
import com.coderslagoon.crypto.estreamj.framework.ICipher;
import com.coderslagoon.crypto.estreamj.framework.ICipherMaker;

public class MICKEY128 extends MICKEYBase {
    static final int R_Mask0  = 0x9c80facf;
    static final int R_Mask1  = 0xe0d18929;
    static final int R_Mask2  = 0xc6be76e1;
    static final int R_Mask3  = 0x730c5d51;
    static final int Comp00   = 0x5dd6f25f;
    static final int Comp01   = 0x79260955;
    static final int Comp02   = 0x79007062;
    static final int Comp03   = 0x37afd931;
    static final int Comp10   = 0x7d191f31;
    static final int Comp11   = 0xfeb63c98;
    static final int Comp12   = 0x7c00c3e0;
    static final int Comp13   = 0x6660e345;
    static final int S_Mask00 = 0xc43c1faf;
    static final int S_Mask01 = 0x0e2fa322;
    static final int S_Mask02 = 0x66e54d81;
    static final int S_Mask03 = 0xd4544b91;
    static final int S_Mask10 = 0x9bf477ab;
    static final int S_Mask11 = 0x70798c90;
    static final int S_Mask12 = 0x6f9a18b6;
    static final int S_Mask13 = 0x6c4b7ee7;

    ///////////////////////////////////////////////////////////////////////////

    int R3;
    int S3;

    ///////////////////////////////////////////////////////////////////////////

    public MICKEY128() {
        super();
        this.key = new int[16];
        this.cached_setupNonce_R = new int[4];
        this.cached_setupNonce_S = new int[4];
    }

    ///////////////////////////////////////////////////////////////////////////

    static final void clockR(
          int input_bit,
          int control_bit,
          int[] R,
          int[] S) {
        int Feedback_bit;
        int Carry0, Carry1, Carry2;

        Feedback_bit = ((R[3] >>> 31) & 1) ^ input_bit;
        Carry0 = (R[0] >>> 31) & 1;
        Carry1 = (R[1] >>> 31) & 1;
        Carry2 = (R[2] >>> 31) & 1;

        if (0 != control_bit) {
            R[0] ^= (R[0] << 1);
            R[1] ^= (R[1] << 1) ^ Carry0;
            R[2] ^= (R[2] << 1) ^ Carry1;
            R[3] ^= (R[3] << 1) ^ Carry2;
        }
        else {
            R[0] <<= 1;
            R[1] = (R[1] << 1) ^ Carry0;
            R[2] = (R[2] << 1) ^ Carry1;
            R[3] = (R[3] << 1) ^ Carry2;
        }

        if (0 != Feedback_bit) {
            R[0] ^= R_Mask0;
            R[1] ^= R_Mask1;
            R[2] ^= R_Mask2;
            R[3] ^= R_Mask3;
        }
    }

    static final void clockS(
      int input_bit,
      int control_bit,
      int[] R,
      int[] S) {
        int Feedback_bit;
        int Carry0, Carry1, Carry2;

        Feedback_bit = ((S[3] >>> 31) & 1) ^ input_bit;
        Carry0 = (S[0] >>> 31) & 1;
        Carry1 = (S[1] >>> 31) & 1;
        Carry2 = (S[2] >>> 31) & 1;

        S[0] = (S[0] << 1) ^ ((S[0] ^ Comp00) & ((S[0] >>> 1) ^ (S[1] << 31) ^ Comp10) & 0xfffffffe);
        S[1] = (S[1] << 1) ^ ((S[1] ^ Comp01) & ((S[1] >>> 1) ^ (S[2] << 31) ^ Comp11)) ^ Carry0;
        S[2] = (S[2] << 1) ^ ((S[2] ^ Comp02) & ((S[2] >>> 1) ^ (S[3] << 31) ^ Comp12)) ^ Carry1;
        S[3] = (S[3] << 1) ^ ((S[3] ^ Comp03) & ((S[3] >>> 1) ^ Comp13) & 0x7fffffff) ^ Carry2;

        if (0 != Feedback_bit) {
            if (0 != control_bit) {
                S[0] ^= S_Mask10;
                S[1] ^= S_Mask11;
                S[2] ^= S_Mask12;
                S[3] ^= S_Mask13;
            }
            else {
                S[0] ^= S_Mask00;
                S[1] ^= S_Mask01;
                S[2] ^= S_Mask02;
                S[3] ^= S_Mask03;
            }
        }
    }

    static final int clockKG1(
            int input_bit,
            int[] R,
            int[] S) {
        int Keystream_bit;
        int control_bit_r;
        int control_bit_s;

        Keystream_bit = (R[0] ^ S[0]) & 1;
        control_bit_r = ((S[1] >>> 11) ^ (R[2] >>> 21)) & 1;
        control_bit_s = ((R[1] >>> 10) ^ (S[2] >>> 21)) & 1;

        clockR((S[2] & 1) ^ input_bit, control_bit_r, R, S);
        clockS(input_bit, control_bit_s, R, S);

        return Keystream_bit;
    }

    ///////////////////////////////////////////////////////////////////////////

    @Override
    public void setNonceSize(int nsize) {
        this.nsize = nsize;
    }

    ///////////////////////////////////////////////////////////////////////////

    public int getKeySize() {
        return 16;  // 128bit
    }

    public void process(
            byte[] inBuf,
            int inOfs,
            byte[] outBuf,
            int outOfs,
            int len) throws ESJException {
        int inEnd;
        int reg;
        int Feedback_bit;
        int Carry0, Carry1, Carry2;
        int control_bit_r;
        int control_bit_s;
        int R0, R1, R2, R3;
        int S0, S1, S2, S3;

        R0 = this.R0;
        R1 = this.R1;
        R2 = this.R2;
        R3 = this.R3;
        S0 = this.S0;
        S1 = this.S1;
        S2 = this.S2;
        S3 = this.S3;

        inEnd = inOfs + len;
        while (inOfs < inEnd) {
            reg = inBuf[inOfs++];

            for (int s = 7; s >= 0; s--) {
                reg ^= ((R0 ^ S0) & 1) << s;

                control_bit_r = ((S1 >>> 11) ^ (R2 >>> 21)) & 1;
                control_bit_s = ((R1 >>> 10) ^ (S2 >>> 21)) & 1;

                Feedback_bit = (R3 >>> 31) & 1;
                Carry0 = (R0 >>> 31) & 1;
                Carry1 = (R1 >>> 31) & 1;
                Carry2 = (R2 >>> 31) & 1;

                if (0 != control_bit_r) {
                    R0 ^= (R0 << 1);
                    R1 ^= (R1 << 1) ^ Carry0;
                    R2 ^= (R2 << 1) ^ Carry1;
                    R3 ^= (R3 << 1) ^ Carry2;
                }
                else {
                    R0 <<= 1;
                    R1 = (R1 << 1) ^ Carry0;
                    R2 = (R2 << 1) ^ Carry1;
                    R3 = (R3 << 1) ^ Carry2;
                }

                if (0 != Feedback_bit) {
                    R0 ^= R_Mask0;
                    R1 ^= R_Mask1;
                    R2 ^= R_Mask2;
                    R3 ^= R_Mask3;
                }

                Feedback_bit = (S3 >>> 31) & 1;
                Carry0 = (S0 >>> 31) & 1;
                Carry1 = (S1 >>> 31) & 1;
                Carry2 = (S2 >>> 31) & 1;

                S0 = (S0 << 1) ^ ((S0 ^ Comp00) & ((S0 >>> 1) ^ (S1 << 31) ^ Comp10) & 0xfffffffe);
                S1 = (S1 << 1) ^ ((S1 ^ Comp01) & ((S1 >>> 1) ^ (S2 << 31) ^ Comp11)) ^ Carry0;
                S2 = (S2 << 1) ^ ((S2 ^ Comp02) & ((S2 >>> 1) ^ (S3 << 31) ^ Comp12)) ^ Carry1;
                S3 = (S3 << 1) ^ ((S3 ^ Comp03) & ((S3 >>> 1) ^ Comp13) & 0x7fffffff) ^ Carry2;

                if (0 != Feedback_bit) {
                    if (0 != control_bit_s) {
                        S0 ^= S_Mask10;
                        S1 ^= S_Mask11;
                        S2 ^= S_Mask12;
                        S3 ^= S_Mask13;
                    }
                    else {
                        S0 ^= S_Mask00;
                        S1 ^= S_Mask01;
                        S2 ^= S_Mask02;
                        S3 ^= S_Mask03;
                    }
                }
            }

            outBuf[outOfs++] = (byte)reg;
        }

        this.R0 = R0;
        this.R1 = R1;
        this.R2 = R2;
        this.R3 = R3;
        this.S0 = S0;
        this.S1 = S1;
        this.S2 = S2;
        this.S3 = S3;
    }

    public void setupKey(int mode, byte[] key, int ofs) throws ESJException {
        int end = ofs + getKeySize();
        int i = 0;

        while (ofs < end) {
            this.key[i++] = key[ofs++] & 0x0ff;
        }
    }

    public void setupNonce(byte[] nonce, int ofs) throws ESJException {
        int i;
        int iv_or_key_bit;
        int nsize = this.nsize << 3;
        int[] key = this.key;
        int[] R = this.cached_setupNonce_R;
        int[] S = this.cached_setupNonce_S;

        for (i = 0; i < 4; i++) {
            R[i] = 0;
            S[i] = 0;
        }

        for (i = 0; i < nsize; i++) {
            iv_or_key_bit = (nonce[(i >>> 3) + ofs] >>> (7 - (i & 7))) & 1;
            clockKG1(iv_or_key_bit, R, S);
        }

        for (i = 0; i < 128; i++) {
            iv_or_key_bit = (key[i >>> 3] >>> (7 - (i & 7))) & 1;
            clockKG1(iv_or_key_bit, R, S);
        }

        for (i = 0; i < 128; i++) {
            clockKG1(0, R, S);
        }

        this.R0 = R[0];
        this.R1 = R[1];
        this.R2 = R[2];
        this.R3 = R[3];
        this.S0 = S[0];
        this.S1 = S[1];
        this.S2 = S[2];
        this.S3 = S[3];
    }

    ///////////////////////////////////////////////////////////////////////////

    static class Maker implements ICipherMaker {
        public ICipher create() throws ESJException {
            return new MICKEY128();
        }

        public String getName() {
            return "MICKEY128";
        }
    }

    public static void register() {
        Engine.registerCipher(new Maker());
    }
}
