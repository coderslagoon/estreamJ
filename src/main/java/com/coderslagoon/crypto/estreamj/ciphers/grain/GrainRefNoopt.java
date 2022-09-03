package com.coderslagoon.crypto.estreamj.ciphers.grain;

import java.util.Arrays;

import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.ICipher;

public abstract class GrainRefNoopt implements ICipher {
    int[] LFSR;
    int[] NFSR;
    byte[] key;

    public void erase() {
        Arrays.fill(this.LFSR, 0);
        Arrays.fill(this.NFSR, 0);
        Arrays.fill(this.key, (byte)0);
    }

    ///////////////////////////////////////////////////////////////////////////

    protected GrainRefNoopt() {
        this.NFSR = new int[getKeySize() << 3];
        this.LFSR = new int[getKeySize() << 3];
    }

    public int getWordSize() {
        return 1;
    }

    public boolean isPatented() {
        return false;
    }

    public void reset() throws ESJException {
    }

    public void process(
            byte[] inBuf,
            int inOfs,
            byte[] outBuf,
            int outOfs,
            int len) throws ESJException {
        int end = inOfs + len;
        while (inOfs < end) {
            int outbyte = 0;
            for (int j = 0; j < 8; j++) {
                outbyte |= keyStream() << j;
            }
            outBuf[outOfs++] = (byte)(outbyte ^ inBuf[inOfs++]);
        }
    }

    public void setupKey(
            int mode,
            byte[] key,
            int ofs) throws ESJException {
        this.key = new byte[getKeySize()];
        System.arraycopy(key, ofs, this.key, 0, this.key.length);
    }

    public void setupNonce(
            byte[] nonce,
            int ofs) throws ESJException {
        int i,j;
        int ivsize = getNonceSize();
        int keysize = getKeySize();
        int[] nfsr = this.NFSR;
        int[] lfsr = this.LFSR;
        byte[] key = this.key;

        for (i = 0; i < ivsize; ++i) {
            for (j = 0; j < 8; ++j) {
                nfsr[(i << 3) + j] = (key[i] >> j) & 1;
                lfsr[(i << 3) + j] = (nonce[ofs + i] >> j) & 1;
            }
        }

        for (i = ivsize; i < keysize; ++i) {
            for (j = 0; j < 8; ++j) {
                nfsr[(i << 3) + j] = (key[i] >> j) & 1;
                lfsr[(i << 3) + j] = 1;
            }
        }

        int initClocks = getKeySize() << 4;
        int midx = (getKeySize() << 3) - 1;

        for (i = 0; i < initClocks; i++) {
            int outbit = keyStream();

            lfsr[midx] ^= outbit;
            nfsr[midx] ^= outbit;
        }
    }

    protected abstract int keyStream();
}
