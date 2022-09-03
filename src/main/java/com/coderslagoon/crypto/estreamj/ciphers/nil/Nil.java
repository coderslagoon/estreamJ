package com.coderslagoon.crypto.estreamj.ciphers.nil;

import java.util.Arrays;
import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.Engine;
import com.coderslagoon.crypto.estreamj.framework.ICipher;
import com.coderslagoon.crypto.estreamj.framework.ICipherMAC;
import com.coderslagoon.crypto.estreamj.framework.ICipherMaker;

/**
 * THIS IS NOT A REAL CIPHER!
 * Just some pass-through implementation for testing and debugging purposes.
 */
public class Nil implements ICipherMAC {
    public static final int WORD_SIZE = 4;
    public static final int KEY_SIZE = 32;
    public static final int MAC_SIZE = 64;
    public static final int NONCE_SIZE = 17;

    /**
     * for checks: each byte of the MAC passed must always contain this value!
     */
    public static final int MAC_FILL_VALUE = 0xbf;

    boolean gotKey;
    boolean gotNonce;
    boolean finalized;

    public int getKeySize() {
        return KEY_SIZE;
    }

    public int getMacSize() {
        return MAC_SIZE;
    }

    public int getNonceSize() {
        return NONCE_SIZE;
    }

    public int getWordSize() {
        return WORD_SIZE;
    }

    public boolean isPatented() {
        return false;   // although ... :)
    }

    public Nil() {
        reset();
    }

    public void reset() {
        this.gotKey = false;
        this.gotNonce = false;
        this.finalized = false;
    }

    public void setupKey(int mode, byte[] key, int ofs)
        throws ESJException {
        if ((MODE_ENCRYPT == mode || MODE_DECRYPT == mode) &&
                key != null && ofs >= 0 && (ofs + KEY_SIZE) <= key.length) {
            this.gotKey = true;
            return;
        }
        throw new ESJException(
                "Nil.setupKey() - some of the parameters are invalid");
    }

    public void setupNonce(byte[] nonce, int ofs)
        throws ESJException {
        if (nonce != null && ofs >= 0 && (ofs + NONCE_SIZE) <= nonce.length) {
            this.gotNonce = true;
            return;
        }
        throw new ESJException(
                "Nil.setupNonce() - some of the parameters are invalid");
    }

    public void process(
            byte[] inBuf,
            int inOfs,
            byte[] outBuf,
            int outOfs,
            int len) throws ESJException {
        if (null == inBuf || null == outBuf || 0 > inOfs || 0 > outOfs ||
                (inOfs + len) > inBuf.length || (outOfs + len) > outBuf.length) {
            throw new ESJException(
                "Nil.process() - some of the parameters are invalid");
        }
        if (this.finalized) {
            throw new ESJException(
                "Nil.process() - called beyond explicit finalization");
        }
        if (0 != len % getWordSize()) {
            this.finalized = true;
        }

        System.arraycopy(inBuf, inOfs,  outBuf, outOfs,len);
    }

    public void processAAD(byte[] buf, int ofs, int len) throws ESJException {
        if (null == buf || 0 > ofs || (ofs + len) > buf.length) {
            throw new ESJException(
                "Nil.processAAD() - some of the parameters are invalid");
        }
        if (this.finalized) {
            throw new ESJException(
                "Nil.processAAD() - called beyond explicit finalization");
        }
        if (0 != len % getWordSize()) {
            this.finalized = true;
        }
    }

    public void finalize(byte[] macBuf, int macOfs) throws ESJException {
        if (null == macBuf || 0 > macOfs ||
                (macOfs + getMacSize()) > macBuf.length) {
            throw new ESJException("Nil.finalize() - stream is not valid");
        }
        Arrays.fill(
            macBuf,
            macOfs,
            macOfs + MAC_SIZE,
            (byte)MAC_FILL_VALUE);
    }

    public void erase() {
    }

    ///////////////////////////////////////////////////////////////////////////

    static class Maker implements ICipherMaker {
        public ICipher create() throws ESJException {
            return new Nil();
        }

        public String getName() {
            return "Nil";
        }
    }

    public static void register() {
        Engine.registerCipher(new Maker());
    }

}
