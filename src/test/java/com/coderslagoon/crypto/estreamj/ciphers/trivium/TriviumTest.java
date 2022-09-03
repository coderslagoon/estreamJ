package com.coderslagoon.crypto.estreamj.ciphers.trivium;

import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.ICipher;
import com.coderslagoon.crypto.estreamj.framework.Utils;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TriviumTest {
    /** comprehensive test vector,  taken from the original C source code;s
     * output, the very last one (selected the first 64 keystream bytes) */
    static final String[] TEST_VECTOR_0 = {
        "0F62B5085BAE0154A7FA",
        "288FF65DC42B92F960C7",
        "FC9659CB953A37FFE869C13F462FE09902C2B9552D976A4562EA79F6F9540801" +
        "485879265FA2239DE46CF09BEFD3A0FD80BC0B782ED18134F9A0D74DB5A003E5"
    };

    @Test
    public void test1() throws ESJException {
        Trivium tv;
        byte[] key, nonce, ktxt, ltxt, mtxt, ztxt;

        tv = new Trivium();

        key = Utils.hexStrToBytes(TEST_VECTOR_0[0]);
        assertEquals(tv.getKeySize(), key.length);
        nonce = Utils.hexStrToBytes(TEST_VECTOR_0[1]);
        assertEquals(tv.getNonceSize(), nonce.length);
        ktxt = Utils.hexStrToBytes(TEST_VECTOR_0[2]);
        assertEquals(64, ktxt.length);

        tv.setupKey(ICipher.MODE_ENCRYPT, key, 0);
        tv.setupNonce(nonce, 0);

        ltxt = new byte[ktxt.length];
        ztxt = new byte[ktxt.length];
        tv.process(ztxt, 0, ltxt, 0, ztxt.length);
        assertTrue(Utils.arraysEquals(ktxt, 0, ltxt, 0, ltxt.length));

        tv.reset();
        tv.setupKey(ICipher.MODE_DECRYPT, key, 0);
        tv.setupNonce(nonce, 0);
        mtxt = new byte[ktxt.length + 2];
        mtxt[0] = mtxt[mtxt.length - 1] = (byte)0xcc;
        tv.process(ltxt, 0, mtxt, 1, ltxt.length);
        assertTrue(Utils.arraysEquals(ztxt, 0, mtxt, 1, ztxt.length));
        assertEquals((byte)0xcc, mtxt[0]);
        assertEquals((byte)0xcc, mtxt[mtxt.length - 1]);
    }

    public void test2() throws ESJException {
        Trivium tv = new Trivium();

        byte[] key = new byte[1 + tv.getKeySize()];
        byte[] nonce = new byte[1 + tv.getNonceSize()];

        Utils.fillPattern123(key, 1, key.length - 1);
        Utils.fillPattern123(nonce, 1, nonce.length - 1);

        for (int len = 0; len < 513; len++) {
            byte[] ptxt = new byte[1 + len]; ptxt[0] = (byte)0xcc;
            byte[] ctxt = new byte[1 + len]; ctxt[0] = (byte)0xcc;
            byte[] dtxt = new byte[1 + len]; dtxt[0] = (byte)0xcc;

            Utils.fillPattern123(ptxt, 1, len);

            tv.reset();
            tv.setupKey(ICipher.MODE_ENCRYPT, key, 1);
            tv.setupNonce(nonce, 1);
            tv.process(ptxt, 1, ctxt, 1, len);
            assertEquals((byte)0xcc, ptxt[0]);
            assertEquals((byte)0xcc, ctxt[0]);

            key[0]--; nonce[0]--;   // must not affect new key setup

            tv.reset();
            tv.setupKey(ICipher.MODE_DECRYPT, key, 1);
            tv.setupNonce(nonce, 1);
            tv.process(ctxt, 1, dtxt, 1, len);
            assertEquals((byte)0xcc, ctxt[0]);
            assertEquals((byte)0xcc, dtxt[0]);

            assertTrue(Utils.checkPattern123(dtxt, 1, len));
        }
    }
}
