package com.coderslagoon.crypto.estreamj.ciphers.nil;

import java.util.Arrays;

import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.ICipher;
import com.coderslagoon.crypto.estreamj.framework.Utils;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Test to check the Nil cipher implementation, so we know it works like it
 * should as the reference guide for the other ones.
 */
public class NilTest {
    @Test
    public void test0() throws ESJException {
        byte[] key, nonce, mac, inBuf, outBuf;
        Nil nil;

        nil = new Nil();
        key = new byte[1 + nil.getKeySize()];
        mac = new byte[1 + nil.getMacSize() + 1];
        nonce = new byte[1 + nil.getNonceSize()];

        nil.setupKey(ICipher.MODE_ENCRYPT, key, 1);
        nil.setupNonce(nonce, 1);

        inBuf = new byte[1 + 1001 + 1];
        outBuf = new byte[1 + 1001 + 1];

        inBuf[0] = inBuf[1002] = (byte)0xcc;
        outBuf[0] = (byte)0xcc;

        Arrays.fill(outBuf, 0, outBuf.length, (byte)0xcc);

        Utils.fillPattern123(inBuf, 1, 1001);

        assertEquals(0, 1000 % nil.getWordSize());
        nil.process(inBuf, 1, outBuf, 1, 1000);

        assertEquals(0xcc, (outBuf[0]    & 0x0ff));
        assertEquals(0xcc, (outBuf[1001] & 0x0ff));
        assertEquals(0xcc, (outBuf[1002] & 0x0ff));

        assertTrue(Utils.checkPattern123(outBuf, 1, 1000));

        nil.processAAD(inBuf, 42, nil.getWordSize() * 3);

        nil.process(inBuf, 1001, outBuf, 1001, 1);
        try {
            nil.process(inBuf, 0, outBuf, 0, 1);
            fail();
        }
        catch (ESJException esje) {
        }
        try {
            nil.processAAD(inBuf, 0, 1);
            fail();
        }
        catch (ESJException esje) {
        }

        assertEquals(0xcc, (outBuf[0]   & 0x0ff));
        assertEquals(0xcc, (outBuf[1002] & 0x0ff));

        assertTrue(Utils.checkPattern123(outBuf, 1, 1001));

        mac[0] = mac[1 + nil.getMacSize()] = (byte)0xcc;

        nil.finalize(mac, 1);

        assertEquals(0xcc, (mac[0] & 0x0ff));
        assertEquals(0xcc, (mac[1 + nil.getMacSize()] & 0x0ff));
        for (int i = 1; i < 1 + nil.getMacSize(); i++) {
            assertEquals(Nil.MAC_FILL_VALUE, (mac[i] & 0x0ff));
        }

        // try some negative stuff...
        try {
            nil.setupKey(-1, inBuf, 0);
            fail();
        }
        catch (ESJException ese) {
        }
        try {
            nil.setupKey(ICipher.MODE_DECRYPT, null, 0);
            fail();
        }
        catch (ESJException ese) {
        }
    }
}
