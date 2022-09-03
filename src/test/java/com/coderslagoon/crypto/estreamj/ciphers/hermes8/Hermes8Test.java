package com.coderslagoon.crypto.estreamj.ciphers.hermes8;

import java.util.Arrays;

import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.ICipher;
import com.coderslagoon.crypto.estreamj.framework.Utils;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * This test covers Hermes8 (80bit and 128bit variants).
 */
public class Hermes8Test {
    // this vector was created via the sample program provided with the Hermes8
    // reference; 80bit key and full IV were all set to zero
    static final String VECTOR_80_1 =
        "ca8d560ceb92fc2a8b30da9222c2a0c89dccf1ad" +
        "e150e20797dc26a623096c6db8b3c0daf40e1c46";

    // almost the same, but key, iv and plain-text got filled with 0xcc
    // (important to test for integer sign extension flaws)
    static final String VECTOR_80_2 =
        "9eb010f47fbe3d568ff5dfd7fe8155e85d67bd70" +
        "f8e034e824a3af0036f16c314c575879f1a287bc";

    @Test
    public void test80() throws ESJException {
        Hermes8 he;
        byte[] key, nonce, cs, ps, es, ds;

        he = new Hermes8(false);

        cs = Utils.hexStrToBytes(VECTOR_80_1);
        assertEquals(40, cs.length);

        key = new byte[he.getKeySize()];

        he.setupKey(ICipher.MODE_ENCRYPT, key, 0);
        he.setupNonce(new byte[he.getNonceSize()], 0);

        ps = new byte[cs.length];
        es = new byte[cs.length];
        he.process(ps, 0, es, 0, cs.length);
        assertTrue(Utils.arraysEquals(es, 0, cs, 0, cs.length));

        // test decryption as well
        ds = new byte[cs.length];
        Arrays.fill(ds, (byte)0xcc);
        he.setupKey(ICipher.MODE_DECRYPT, key, 0);
        he.setupNonce(new byte[he.getNonceSize()], 0);
        he.process(es, 0, ds, 0, es.length);
        assertTrue(Utils.arraysEquals(ds, 0, ps, 0, ds.length));

        ///////////////////////////////////////////////////////////////////////

        cs = Utils.hexStrToBytes(VECTOR_80_2);
        assertEquals(40, cs.length);

        key = new byte[he.getKeySize()];
        Arrays.fill(key, (byte)0xcc);
        he.setupKey(ICipher.MODE_ENCRYPT, key, 0);

        nonce = new byte[he.getNonceSize()];
        Arrays.fill(nonce, (byte)0xcc);
        he.setupNonce(nonce, 0);

        ps = new byte[cs.length];
        Arrays.fill(ps, (byte)0xcc);
        es = new byte[cs.length];
        he.process(ps, 0, es, 0, cs.length);

        assertTrue(Utils.arraysEquals(es, 0, cs, 0, cs.length));
    }

    ///////////////////////////////////////////////////////////////////////////

    // same as for VECTOR_80_1, just with a 128bit all-zero-key
    static final String VECTOR_128_1 =
        "a63c3efed3f83572e2afd5e8fbefab75aab82ff6" +
        "afb628a7f8f4759ec7e91de8aa924eb44132292b";

    @Test
    public void test128() throws ESJException {
        Hermes8 he;
        byte[] key, cs, ps, es, ds;

        he = new Hermes8(true);

        cs = Utils.hexStrToBytes(VECTOR_128_1);
        assertEquals(40, cs.length);

        key = new byte[he.getKeySize()];

        he.setupKey(ICipher.MODE_ENCRYPT, key, 0);
        he.setupNonce(new byte[he.getNonceSize()], 0);

        ps = new byte[cs.length];
        es = new byte[cs.length];
        he.process(ps, 0, es, 0, cs.length);
        assertTrue(Utils.arraysEquals(es, 0, cs, 0, cs.length));

        ds = new byte[cs.length];
        Arrays.fill(ds, (byte)0xcc);
        he.setupKey(ICipher.MODE_DECRYPT, key, 0);
        he.setupNonce(new byte[he.getNonceSize()], 0);
        he.process(es, 0, ds, 0, es.length);
        assertTrue(Utils.arraysEquals(ds, 0, ps, 0, ds.length));
    }
}
