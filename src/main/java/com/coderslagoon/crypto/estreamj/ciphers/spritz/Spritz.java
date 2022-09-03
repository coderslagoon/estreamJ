package com.coderslagoon.crypto.estreamj.ciphers.spritz;

import java.util.Arrays;

import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.Engine;
import com.coderslagoon.crypto.estreamj.framework.ICipher;
import com.coderslagoon.crypto.estreamj.framework.ICipherMaker;
import com.coderslagoon.crypto.estreamj.framework.Utils;

public class Spritz implements ICipher {

    static final int N = 256;

    static final int[] S_INIT = new int[N];
    static {
        for (int i = 0; i < S_INIT.length; i++)
            S_INIT[i] = i;
    }

    private int[] s;
    private int a, i, j, k, w, z;

    private void initializeState() {
        this.s = S_INIT.clone();
        this.a = this.i = this.j = this.k = this.z = 0;
        this.w = 1;
    }

    private void update() {
        this.i += this.w;
        this.i &= 255;
        int y = (this.j + this.s[this.i]) & 255;
        this.j = (this.k + this.s[y]) & 255;
        this.k = (this.i + this.k + this.s[this.j]) & 255;
        int t = this.s[this.i & 0xff];
        this.s[this.i] = this.s[this.j];
        this.s[this.j] = t;
    }

    private int output() {
        int y1 = (this.z + this.k) & 255;
        int x1 = (this.i + this.s[y1]) & 255;
        int y2 = (this.j + this.s[x1]) & 255;
        this.z = this.s[y2];
        return this.z;
    }

    private void crush() {
        for (int v = 0; v < N / 2; v++) {
            int y = (N - 1) - v;
            int x1 = this.s[v];
            int x2 = this.s[y];
            if (x1 > x2) {
                this.s[v] = x2;
                this.s[y] = x1;
            } else {
                this.s[v] = x1;
                this.s[y] = x2;
            }
        }
    }

    private void whip() {
        for (int v = 0; v < N * 2; v++) {
            update();
        }
        this.w += 2;
    }

    private void shuffle() {
        whip();
        crush();
        whip();
        crush();
        whip();
        this.a = 0;
    }

    private void absorbStop() {
        if (this.a == N / 2) {
            shuffle();
        }
        this.a++;
    }

    private void absorbNibble(int x) {
        if (this.a == N / 2) {
            shuffle();
        }
        int y = (N / 2 + x) & 255;
        int t = this.s[this.a];
        this.s[this.a] = this.s[y];
        this.s[y] = t;
        this.a++;
    }

    private void absorbByte(int b) {
        absorbNibble(b & 15);
        absorbNibble((b >>> 4) & 15);
    }

    private void absorb(byte[] msg, int ofs, int len) {
        for (int end = ofs + len; ofs < end; ofs++) {
            absorbByte(msg[ofs] & 255);
        }
    }

    private int drip() {
        if (this.a > 0) {
            shuffle();
        }
        update();
        return output();
    }

    private void keySetup(byte[] key, int ofs, int len) {
        initializeState();
        absorb(key, ofs, len);
    }

    private void squeeze(byte[] out, int ofs, int len) {
        if (this.a > 0) {
            shuffle();
        }
        for (int end = ofs + len; ofs < end; ofs++) {
            out[ofs] = (byte)drip();
        }
    }

    public static boolean isCompatible() {
        String[][] REF_DATA_STREAM = {
            { "ABC"    , "779a8e01f9e9cbc0" },
            { "spam"   , "f0609a1df143cebf" },
            { "arcfour", "1afa8b5ee337dbc7" }
        };
        for (String[] refData : REF_DATA_STREAM) {
            Spritz s = new Spritz();
            byte[] key = refData[0].getBytes();
            s.initializeState();
            s.absorb(key, 0, key.length);
            byte[] expected = Utils.hexStrToBytes(refData[1]);
            byte[] out = new byte[3];
            for (int i = 0; i < expected.length; i++) {
                out[0] = 55;
                out[2] = 111;
                s.squeeze(out, 1, 1);
                if (out[1] != expected[i])
                    return false;
            }
        }
        return true;
    }

    ///////////////////////////////////////////////////////////////////////////

    void cipherInit(byte[] key, int keyOfs, int keyLen,
                    byte[] iv , int ivOfs , int ivLen) {
        keySetup(key, keyOfs, keyLen);
        absorbStop();
        absorb(iv, ivOfs, ivLen);
    }

    void cipherEncrypt(byte[] in , int inOfs , int len,
                       byte[] out, int outOfs) {
        for (int i = 0; i < len; i++)
            out[outOfs + i] = (byte)(in[inOfs + i] + drip());
    }

    void cipherDecrypt(byte[] in , int inOfs , int len,
                       byte[] out, int outOfs) {
        for (int i = 0; i < len; i++)
            out[outOfs + i] = (byte)(in[inOfs + i] - drip());
    }

    ///////////////////////////////////////////////////////////////////////////

    byte[] key;
    int    mode;

    ///////////////////////////////////////////////////////////////////////////

    public int getKeySize() {
        return 32;
    }

    public int getNonceSize() {
        return 16;
    }

    public int getWordSize() {
        return 1;
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
        if (MODE_ENCRYPT == this.mode)
            this.cipherEncrypt(inBuf, inOfs, len, outBuf, outOfs);
        else
            this.cipherDecrypt(inBuf, inOfs, len, outBuf, outOfs);
    }

    public void reset() throws ESJException {
    }

    public void setupKey(int mode, byte[] key, int ofs) throws ESJException {
        this.mode = mode;
        this.key = new byte[getKeySize()];
        System.arraycopy(key, ofs, this.key, 0, this.key.length);
    }

    public void setupNonce(byte[] nonce, int ofs) throws ESJException {
        this.cipherInit(this.key, 0, this.key.length,
                        nonce, ofs, getNonceSize());
    }

    public void erase() {
        Arrays.fill(this.s, 0);
        this.a = this.i = this.j = this.k = this.w = this.z = 0;
        if (null != this.key)
            Arrays.fill(this.key, (byte)0);
    }

    ///////////////////////////////////////////////////////////////////////////

    static class Maker implements ICipherMaker {
        public ICipher create() throws ESJException {
            return new Spritz();
        }

        public String getName() {
            return "Spritz";
        }
    }

    public static void register() {
        Engine.registerCipher(new Maker());
    }
}
