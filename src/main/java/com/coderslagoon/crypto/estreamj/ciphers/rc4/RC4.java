package com.coderslagoon.crypto.estreamj.ciphers.rc4;

import java.util.Arrays;

import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.Engine;
import com.coderslagoon.crypto.estreamj.framework.ICipher;
import com.coderslagoon.crypto.estreamj.framework.ICipherMaker;

/**
 * RC4 implementation, 128bit keys and 128 bit nonce size. Key and nonce are
 * concatenated and form together a 256bit RC4 key. Discarding of initial key
 * stream data is supported, the default is set to 1024 bytes.
 */
public class RC4 implements ICipher {
    static final int MAX_KEY_SIZE = 256;

    // according to <Ilya Mironov, "(Not So) Random Shuffles of RC4",
    // in Proceedings of CRYPTO 2002. http://citeseer.ist.psu.edu/531224.html>
    static final int DEF_INITIAL_DISCARD_SIZE = 512;

    ///////////////////////////////////////////////////////////////////////////

    int x, y;
    int[] state = new int[MAX_KEY_SIZE];
    byte[] rkey = new byte[32];

    int initialDiscardSize;

    public void erase() {
        Arrays.fill(this.state, 0);
        Arrays.fill(this.rkey, (byte)0);
        this.x = this. y = 0;
    }

    ///////////////////////////////////////////////////////////////////////////

    public RC4(int initialDiscardSize) {
        this.initialDiscardSize = (-1 == initialDiscardSize) ?
               DEF_INITIAL_DISCARD_SIZE : initialDiscardSize;
    }

    ///////////////////////////////////////////////////////////////////////////

    public int getKeySize() {
        return 16;
    }

    public int getNonceSize() {
        return 16;
    }

    public int getWordSize() {
        return 1;
    }

    public boolean isPatented() {
        return true;
    }

    public void process(
            byte[] inBuf,
            int inOfs,
            byte[] outBuf,
            int outOfs,
            int len) throws ESJException {
        int i;
        int x = this.x;
        int y = this.y;
        int[] state = this.state;
        int sx, sy;

        for (i = 0; i < len; i++) {  // 3 adds, 1 store for counting
            // TODO: unroll that

            x = (x + 1) & 0xff;
            sx = state[x];
            y = (y + sx) & 0xff;
            sy = state[y];
            state[y] = sx;
            state[x] = sy;

            outBuf[outOfs + i] = (byte)(inBuf[inOfs + i] ^
                    state[(sx + sy) & 0xff]);
        }

        this.x = x;
        this.y = y;
    }

    public void reset() throws ESJException {
        // nothing to do, key stays preserved
    }

    public void setupKey(
            int mode,
            byte[] key,
            int ofs) throws ESJException {
        System.arraycopy(key, ofs, this.rkey, 0, 16);
    }

    public void setupNonce(
            byte[] nonce,
            int ofs) throws ESJException {
        int x, sx, y, sy, c;
        int[] state = this.state;
        byte[] rkey = this.rkey;

        System.arraycopy(nonce, ofs, this.rkey, 16, 16);

        for (x = 0; x < MAX_KEY_SIZE; x++) {
            state[x] = x;
        }

        for (x = 0, y = 0; x < MAX_KEY_SIZE; x++) {
            sx = state[x];

            y += sx + rkey[x & 0x1f] & 0x0ff;
            y &= 0x0ff;

            state[x] = state[y];
            state[y] = sx;
        }

        this.x = this.y = x = y = 0;

        for (c = this.initialDiscardSize; 0 < c; c--) {
            x = (x + 1) & 0xff;
            sx = state[x];
            y = (y + sx) & 0xff;
            sy = state[y];
            state[y] = sx;
            state[x] = sy;
        }

        this.x = x;
        this.y = y;
    }

    ///////////////////////////////////////////////////////////////////////////

    static class Maker implements ICipherMaker {
        public ICipher create() throws ESJException {
            return new RC4(-1);
        }

        public String getName() {
            return "RC4";
        }
    }

    public static void register() {
        Engine.registerCipher(new Maker());
    }
}
