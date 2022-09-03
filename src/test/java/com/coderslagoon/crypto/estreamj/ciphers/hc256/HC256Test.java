package com.coderslagoon.crypto.estreamj.ciphers.hc256;

import java.util.Arrays;

import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.ICipher;
import com.coderslagoon.crypto.estreamj.framework.Utils;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class HC256Test {
    static final byte[] VECTOR_ALL_ZERO = {
        (byte)0x5b,(byte)0x07,(byte)0x89,(byte)0x85,(byte)0xd8,(byte)0xf6,(byte)0xf3,(byte)0x0d,
        (byte)0x42,(byte)0xc5,(byte)0xc0,(byte)0x2f,(byte)0xa6,(byte)0xb6,(byte)0x79,(byte)0x51,
        (byte)0x53,(byte)0xf0,(byte)0x65,(byte)0x34,(byte)0x80,(byte)0x1f,(byte)0x89,(byte)0xf2,
        (byte)0x4e,(byte)0x74,(byte)0x24,(byte)0x8b,(byte)0x72,(byte)0x0b,(byte)0x48,(byte)0x18
    };

    @Test
    public void testAllZero() throws ESJException {
        HC256 hc = new HC256();
        byte[] ks;

        hc.setupKey(ICipher.MODE_ENCRYPT, new byte[hc.getKeySize()], 0);
        hc.setupNonce(new byte[hc.getNonceSize()], 0);

        ks = new byte[32];
        Arrays.fill(ks, (byte)0);

        hc.process(ks, 0, ks, 0, ks.length);

        assertTrue(Utils.arraysEquals(
                ks, 0, VECTOR_ALL_ZERO, 0, VECTOR_ALL_ZERO.length));

        hc.reset();
        Arrays.fill(ks, (byte)0);
        hc.process(ks, 0, ks, 0, ks.length);
        assertTrue(Utils.arraysEquals(
                ks, 0, VECTOR_ALL_ZERO, 0, VECTOR_ALL_ZERO.length));

        // (test decryption at least once)
        hc.reset();
        hc.process(ks, 0, ks, 0, ks.length);

        assertTrue(Utils.arraysEquals(
                ks, 0, new byte[ks.length], 0, ks.length));
    }

    ///////////////////////////////////////////////////////////////////////////

    static final byte[] VECTOR_IV0_EQU_1 = {
        (byte)0xaf,(byte)0xe2,(byte)0xa2,(byte)0xbf,(byte)0x4f,(byte)0x17,(byte)0xce,(byte)0xe9,
        (byte)0xfe,(byte)0xc2,(byte)0x05,(byte)0x8b,(byte)0xd1,(byte)0xb1,(byte)0x8b,(byte)0xb1,
        (byte)0x5f,(byte)0xc0,(byte)0x42,(byte)0xee,(byte)0x71,(byte)0x2b,(byte)0x31,(byte)0x01,
        (byte)0xdd,(byte)0x50,(byte)0x1f,(byte)0xc6,(byte)0x0b,(byte)0x08,(byte)0x2a,(byte)0x50
    };

    static final byte[] VECTOR_KEY0_EQU_85 = {
        (byte)0x1c,(byte)0x40,(byte)0x4a,(byte)0xfe,(byte)0x4f,(byte)0xe2,(byte)0x5f,(byte)0xed,
        (byte)0x95,(byte)0x8f,(byte)0x9a,(byte)0xd1,(byte)0xae,(byte)0x36,(byte)0xc0,(byte)0x6f,
        (byte)0x88,(byte)0xa6,(byte)0x5a,(byte)0x3c,(byte)0xc0,(byte)0xab,(byte)0xe2,(byte)0x23,
        (byte)0xae,(byte)0xb3,(byte)0x90,(byte)0x2f,(byte)0x42,(byte)0x0e,(byte)0xd3,(byte)0xa8
    };

    @Test
    public void test2() throws ESJException {
        HC256 hc = new HC256();
        byte[] key, iv, ks, out;

        iv = new byte[hc.getNonceSize() + 1];
        iv[0] = (byte)0xcc;
        iv[1] = 1;

        hc.setupKey(ICipher.MODE_ENCRYPT, new byte[hc.getKeySize()], 0);
        hc.setupNonce(iv, 1);
        assertEquals(0xcc, (iv[0] & 0x0ff));

        ks = new byte[32];
        Arrays.fill(ks, (byte)0);
        out = new byte[34];
        out[0] = out[33] = (byte)0xcc;

        hc.process(ks, 0, out, 1, ks.length);
        assertEquals(0xcc, (out[0] & 0x0ff));
        assertEquals(0xcc, (out[33] & 0x0ff));

        assertTrue(Utils.arraysEquals(
                out, 1, VECTOR_IV0_EQU_1, 0, VECTOR_IV0_EQU_1.length));

        iv = null;
        hc.reset();

        key = new byte[hc.getKeySize() + 1];
        key[0] = (byte)0xcc;
        key[1] = 0x55;

        hc.setupKey(ICipher.MODE_DECRYPT, key, 1);
        hc.setupNonce(new byte[hc.getNonceSize()], 0);
        assertEquals(0xcc, (key[0] & 0x0ff));

        Arrays.fill(ks, (byte)0);
        hc.process(ks, 0, out, 2, ks.length);

        assertTrue(Utils.arraysEquals(
                out, 2, VECTOR_KEY0_EQU_85, 0, VECTOR_KEY0_EQU_85.length));
    }
}
