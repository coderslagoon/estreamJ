package com.coderslagoon.crypto.estreamj.ciphers.salsa20;

import java.util.Arrays;

import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.Engine;
import com.coderslagoon.crypto.estreamj.framework.ICipher;
import com.coderslagoon.crypto.estreamj.framework.ICipherMaker;
import com.coderslagoon.crypto.estreamj.framework.Utils;

public class Salsa20 implements ICipher {
    int[] input = new int[16];
    int[] input_bak;

    byte[] cached_process_output = new byte[64];
    int[] cached_wordToByte_x = new int[16];

    static final byte[] sigma = "expand 32-byte k".getBytes();
    static final byte[] tau = "expand 16-byte k".getBytes();

    public void erase() {
        Arrays.fill(this.input, 0);
        Arrays.fill(this.input_bak, 0);
        Arrays.fill(this.cached_process_output, (byte)0);
        Arrays.fill(this.cached_wordToByte_x, 0);
    }

    ///////////////////////////////////////////////////////////////////////////

    public int getKeySize() {
        return 256 >> 3;    // 256bit version only
    }

    public int getNonceSize() {
        return 8;
    }

    public int getWordSize() {
        return 64;
    }

    public boolean isPatented() {
        return false;
    }

    private void wordToByte(byte[] outp, int[] inp) {
        int[] x = this.cached_wordToByte_x;
        int i, s;

        System.arraycopy(inp, 0, x, 0, x.length);

        for (i = 20; i > 0; i -= 2) {
            s = x[ 0] + x[12]; x[ 4] ^= (s <<  7) | (s >>> (32 -  7));
            s = x[ 4] + x[ 0]; x[ 8] ^= (s <<  9) | (s >>> (32 -  9));
            s = x[ 8] + x[ 4]; x[12] ^= (s << 13) | (s >>> (32 - 13));
            s = x[12] + x[ 8]; x[ 0] ^= (s << 18) | (s >>> (32 - 18));
            s = x[ 5] + x[ 1]; x[ 9] ^= (s <<  7) | (s >>> (32 -  7));
            s = x[ 9] + x[ 5]; x[13] ^= (s <<  9) | (s >>> (32 -  9));
            s = x[13] + x[ 9]; x[ 1] ^= (s << 13) | (s >>> (32 - 13));
            s = x[ 1] + x[13]; x[ 5] ^= (s << 18) | (s >>> (32 - 18));
            s = x[10] + x[ 6]; x[14] ^= (s <<  7) | (s >>> (32 -  7));
            s = x[14] + x[10]; x[ 2] ^= (s <<  9) | (s >>> (32 -  9));
            s = x[ 2] + x[14]; x[ 6] ^= (s << 13) | (s >>> (32 - 13));
            s = x[ 6] + x[ 2]; x[10] ^= (s << 18) | (s >>> (32 - 18));
            s = x[15] + x[11]; x[ 3] ^= (s <<  7) | (s >>> (32 -  7));
            s = x[ 3] + x[15]; x[ 7] ^= (s <<  9) | (s >>> (32 -  9));
            s = x[ 7] + x[ 3]; x[11] ^= (s << 13) | (s >>> (32 - 13));
            s = x[11] + x[ 7]; x[15] ^= (s << 18) | (s >>> (32 - 18));
            s = x[ 0] + x[ 3]; x[ 1] ^= (s <<  7) | (s >>> (32 -  7));
            s = x[ 1] + x[ 0]; x[ 2] ^= (s <<  9) | (s >>> (32 -  9));
            s = x[ 2] + x[ 1]; x[ 3] ^= (s << 13) | (s >>> (32 - 13));
            s = x[ 3] + x[ 2]; x[ 0] ^= (s << 18) | (s >>> (32 - 18));
            s = x[ 5] + x[ 4]; x[ 6] ^= (s <<  7) | (s >>> (32 -  7));
            s = x[ 6] + x[ 5]; x[ 7] ^= (s <<  9) | (s >>> (32 -  9));
            s = x[ 7] + x[ 6]; x[ 4] ^= (s << 13) | (s >>> (32 - 13));
            s = x[ 4] + x[ 7]; x[ 5] ^= (s << 18) | (s >>> (32 - 18));
            s = x[10] + x[ 9]; x[11] ^= (s <<  7) | (s >>> (32 -  7));
            s = x[11] + x[10]; x[ 8] ^= (s <<  9) | (s >>> (32 -  9));
            s = x[ 8] + x[11]; x[ 9] ^= (s << 13) | (s >>> (32 - 13));
            s = x[ 9] + x[ 8]; x[10] ^= (s << 18) | (s >>> (32 - 18));
            s = x[15] + x[14]; x[12] ^= (s <<  7) | (s >>> (32 -  7));
            s = x[12] + x[15]; x[13] ^= (s <<  9) | (s >>> (32 -  9));
            s = x[13] + x[12]; x[14] ^= (s << 13) | (s >>> (32 - 13));
            s = x[14] + x[13]; x[15] ^= (s << 18) | (s >>> (32 - 18));
        }

        for (i = 0; i < 16; i++) {
            Utils.writeInt32LE(x[i] + inp[i], outp, i << 2);
        }
    }

    public void process(
            byte[] inBuf,
            int inOfs,
            byte[] outBuf,
            int outOfs,
            int len) throws ESJException {
        byte[] output = this.cached_process_output;
        int[] input = this.input;
        int i, c;

        if (0 < len) {
            for (;;) {
                wordToByte(output, input);
                if (0 == ++input[8]) {
                    input[9]++; // we don't stop at 2^70+ bytes for now
                }

                c = (len <= 64) ? len : 64;
                for (i = 0; i < c; i++) {
                    outBuf[outOfs + i] = (byte)(inBuf[inOfs + i] ^ output[i]);
                }
                len -= 64;
                if (1 > len) {
                    return;
                }
                inOfs += 64;
                outOfs += 64;
            }
        }
    }

    public void reset() throws ESJException {
        if (null == this.input_bak) {
            throw new ESJException("Salsa20 instance hasn't been set up yet");
        }
        System.arraycopy(this.input_bak, 0, this.input, 0, this.input.length);
    }

    public void setupKey(int mode, byte[] key, int ofs) throws ESJException {
        byte[] constants;

        this.input[1] = Utils.readInt32LE(key, ofs     );
        this.input[2] = Utils.readInt32LE(key, ofs +  4);
        this.input[3] = Utils.readInt32LE(key, ofs +  8);
        this.input[4] = Utils.readInt32LE(key, ofs + 12);

        if (256 == (getKeySize() << 3)) {
            ofs += 16;
            constants = sigma;
        }
        else {
            constants = tau;    // not used right now
        }

        this.input[11] = Utils.readInt32LE(key, ofs +  0);
        this.input[12] = Utils.readInt32LE(key, ofs +  4);
        this.input[13] = Utils.readInt32LE(key, ofs +  8);
        this.input[14] = Utils.readInt32LE(key, ofs + 12);

        this.input[ 0] = Utils.readInt32LE(constants,  0);
        this.input[ 5] = Utils.readInt32LE(constants,  4);
        this.input[10] = Utils.readInt32LE(constants,  8);
        this.input[15] = Utils.readInt32LE(constants, 12);
    }

    public void setupNonce(byte[] nonce, int ofs) throws ESJException {
        this.input[6] = Utils.readInt32LE(nonce, ofs);
        this.input[7] = Utils.readInt32LE(nonce, ofs + 4);
        this.input[8] = 0;
        this.input[9] = 0;

        this.input_bak = this.input.clone();
    }

    ///////////////////////////////////////////////////////////////////////////

    static class Maker implements ICipherMaker {
        public ICipher create() throws ESJException {
            return new Salsa20();
        }

        public String getName() {
            return "Salsa20";
        }
    }

    public static void register() {
        Engine.registerCipher(new Maker());
    }
}
