package com.coderslagoon.crypto.estreamj.ciphers.rc4;

import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.ICipher;
import com.coderslagoon.crypto.estreamj.framework.Utils;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class RC4Test {
    // (found this test vector on Wikipedia)
    static final String[] TEST_VECTOR_1 = {
        "0123456789abcdef0123456789abcdef",     // key
        "0123456789abcdef0123456789abcdef",     // nonce
        "123456789abcdef0123456789abcdef0123456789abcdef012345678", // ptxt
        "66a0949f8af7d6891f7f832ba833c00c892ebe30143ce28740011ecf", // ctxt
    };

    @Test
    public void test1() throws ESJException {
        RC4 rcf;
        byte[] key, nonce, ptxt, ctxt, etxt, dtxt;

        rcf = new RC4(0);

        key = Utils.hexStrToBytes(TEST_VECTOR_1[0]);
        assertEquals(rcf.getKeySize(), key.length);
        nonce = Utils.hexStrToBytes(TEST_VECTOR_1[1]);
        assertEquals(rcf.getNonceSize(), nonce.length);
        ptxt = Utils.hexStrToBytes(TEST_VECTOR_1[2]);
        assertEquals(28, ptxt.length);
        ctxt = Utils.hexStrToBytes(TEST_VECTOR_1[3]);
        assertEquals(ptxt.length, ctxt.length);

        rcf.setupKey(ICipher.MODE_ENCRYPT, key, 0);
        rcf.setupNonce(nonce, 0);

        etxt = new byte[ptxt.length];
        rcf.process(ptxt, 0, etxt, 0, ptxt.length);
        assertTrue(Utils.arraysEquals(etxt, 0, ctxt, 0, ctxt.length));

        rcf.reset();
        rcf.setupKey(ICipher.MODE_DECRYPT, key, 0);
        rcf.setupNonce(nonce, 0);
        dtxt = new byte[ctxt.length];
        rcf.process(ctxt, 0, dtxt, 0, dtxt.length);
        assertTrue(Utils.arraysEquals(dtxt, 0, ptxt, 0, ptxt.length));
    }
}
