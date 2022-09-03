package com.coderslagoon.crypto.estreamj.ciphers.aes;

import java.util.Arrays;

import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.Engine;
import com.coderslagoon.crypto.estreamj.framework.ICipher;
import com.coderslagoon.crypto.estreamj.framework.ICipherMaker;
import com.coderslagoon.crypto.estreamj.framework.Utils;

public class AESCTR implements ICipher {
    AES aes;
    byte[] counter;

    byte[] cached_processBytes_reg = new byte[AES.BLOCK_SIZE];

    ///////////////////////////////////////////////////////////////////////////

    public AESCTR(boolean lean) {
        if (lean) {
            this.aes = new AESLean();
        }
        else {
            this.aes = new AESMean();
        }
        this.counter = new byte[AES.BLOCK_SIZE];
    }

    ///////////////////////////////////////////////////////////////////////////

    public int getKeySize() {
        return 16;  // use 128bit keys
    }

    public int getNonceSize() {
        return AES.BLOCK_SIZE;
    }

    public int getWordSize() {
        return AES.BLOCK_SIZE;
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
        int i;
        byte[] counter = this.counter;
        byte[] reg = this.cached_processBytes_reg;

        while (16 <= len) {
            this.aes.processBlock(counter, 0, reg, 0);

            i = 0;
            while (i < 16) {
                outBuf[outOfs + i] = (byte)(inBuf[inOfs + i] ^ reg[i]); i++;
                outBuf[outOfs + i] = (byte)(inBuf[inOfs + i] ^ reg[i]); i++;
                outBuf[outOfs + i] = (byte)(inBuf[inOfs + i] ^ reg[i]); i++;
                outBuf[outOfs + i] = (byte)(inBuf[inOfs + i] ^ reg[i]); i++;
            }

            // the eSTREAM implementation is designed for 32bit counting only,
            // so we have to either stop at 4GB of data in theory or extend out
            // counting (with a little performance hit, of course)

            Utils.writeInt32LE(
                    Utils.readInt32LE(counter, 0) + 1,
                    counter,
                    0);

            len -= 16;
            outOfs += 16;
            inOfs += 16;
        }
        if (0 < len) {
            // very last round
            this.aes.processBlock(counter, 0, reg, 0);
            for (i = 0; i < len; i++) {
                outBuf[outOfs++] = (byte)(inBuf[inOfs++] ^ reg[i]);
            }
        }
    }

    public void reset() throws ESJException {
        // nothing to do here
    }

    public void setupKey(int mode, byte[] key, int ofs) throws ESJException {
        this.aes.init(
                true,       // always encrypt
                key,
                0,
                getKeySize());
    }

    public void setupNonce(byte[] nonce, int ofs) throws ESJException {
        System.arraycopy(
                nonce,
                ofs,
                this.counter,
                0,
                this.counter.length);
    }


    public void erase() {
        this.aes.erase();
        Arrays.fill(this.cached_processBytes_reg, (byte)0);
        if (null != this.counter)
            Arrays.fill(this.counter, (byte)0);
    }

    ///////////////////////////////////////////////////////////////////////////

    static class Maker implements ICipherMaker {
        boolean lean;

        public Maker(boolean lean) {
            this.lean = lean;
        }

        public ICipher create() throws ESJException {
            return new AESCTR(this.lean);
        }

        public String getName() {
            return this.lean ? "AESCTR128_lean" : "AESCTR128_mean";
        }
    }

    public static void register() {
        Engine.registerCipher(new Maker(true));
        Engine.registerCipher(new Maker(false));
    }
}
