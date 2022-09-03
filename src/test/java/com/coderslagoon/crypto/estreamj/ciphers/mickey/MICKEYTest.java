package com.coderslagoon.crypto.estreamj.ciphers.mickey;

import java.util.Arrays;

import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.ICipher;
import com.coderslagoon.crypto.estreamj.framework.Utils;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNotEquals;

/**
 * This test covers both MICKEY and MICKEY128.
 */
public class MICKEYTest {
    static final String[][] VECTORS = {
        new String[] {
            "cc123456789abcdef01234",               // key
            "cc21436587",                           // nonce
            "cce3680dbb87ca40e9a3c02a475f3418a8"    // keystream
        },
        new String[] {
            "ccf11a5627ce43b61f8912",
            "cc9c532f8ac3ea4b2ea0f5",
            "ccf1f38184c253eb80a102fb4ff64860f6"
        },
        new String[] {
            "cc3b80fc8c475fc270fa26",
            "cc",
            "cc91e1ccda01e76de98c1ddec1915dd138"
        }
    };

    @Test
    public void testVectors() throws ESJException {
        MICKEY mck;
        byte[] key, nonce, ks, ps, es, ds;

        mck = new MICKEY();

        for (String[] vector : VECTORS) {
            key   = Utils.hexStrToBytes(vector[0]); assertNotEquals(null, key);
            nonce = Utils.hexStrToBytes(vector[1]); assertNotEquals(null, nonce);
            ks    = Utils.hexStrToBytes(vector[2]); assertNotEquals(null, ks);

            assertEquals(1 + mck.getKeySize(), key.length);
            assertTrue(0 < nonce.length);
            assertEquals(17, ks.length);

            mck.reset();
            mck.setupKey(ICipher.MODE_ENCRYPT, key, 1);
            mck.setNonceSize(nonce.length - 1);
            mck.setupNonce(nonce, 1);

            ps = new byte[ks.length];
            Arrays.fill(ps, (byte)0);
            es = ps.clone();
            es[0] =
            ps[0] = (byte)0xee;

            mck.process(ps, 1, es, 1, ps.length - 1);
            assertEquals((byte)0xee, es[0]);
            assertTrue(Utils.arraysEquals(es, 1, ks, 1, ks.length - 1));

            // test decryption as well
            mck.reset();
            mck.setupKey(ICipher.MODE_ENCRYPT, key, 1);
            mck.setNonceSize(nonce.length - 1);
            mck.setupNonce(nonce, 1);

            ds = new byte[es.length - 1];
            mck.process(es, 1, ds, 0, ds.length);
            assertTrue(Utils.arraysEquals(ds, 0, ps, 1, ds.length));
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    // same as above, just 48 bits more

    static final String[][] VECTORS128 = {
        new String[] {
            "aa123456789abcdef00123456789abcdef",
            "aa21436587",
            "aa63c5172c40afe1fe0b7bee651f8d145a"

        },
        new String[] {
            "aaf11a5627ce43b61f8912299486094486",
            "aa9c532f8ac3ea4b2ea0f59640308377cc",
            "aa662b477795c1511bc297fb5045f5daad"
        },
        new String[] {
            "aa3b80fc8c475fc270fa26b47064b32d33",
            "aa",
            "aab8fd164c4a1fafb66f83c66f9042acc4"
        }
    };

    @Test
    public void testVectors128() throws ESJException {
        MICKEY128 mck128;
        byte[] key, nonce, ks, ps, es, ds;

        mck128 = new MICKEY128();

        for (String[] vector : VECTORS128) {
            key   = Utils.hexStrToBytes(vector[0]); assertNotEquals(null, key);
            nonce = Utils.hexStrToBytes(vector[1]); assertNotEquals(null, nonce);
            ks    = Utils.hexStrToBytes(vector[2]); assertNotEquals(null, ks);

            assertEquals(1 + mck128.getKeySize(), key.length);
            assertTrue(0 < nonce.length);
            assertEquals(17, ks.length);

            mck128.reset();
            mck128.setupKey(ICipher.MODE_ENCRYPT, key, 1);
            mck128.setNonceSize(nonce.length - 1);
            mck128.setupNonce(nonce, 1);

            ps = new byte[ks.length];
            Arrays.fill(ps, (byte)0);
            es = ps.clone();
            es[0] =
            ps[0] = (byte)0xbb;

            mck128.process(ps, 1, es, 1, ps.length - 1);
            assertEquals((byte)0xbb, es[0]);
            assertTrue(Utils.arraysEquals(es, 1, ks, 1, ks.length - 1));

            mck128.reset();
            mck128.setupKey(ICipher.MODE_ENCRYPT, key, 1);
            mck128.setNonceSize(nonce.length - 1);
            mck128.setupNonce(nonce, 1);

            ds = new byte[es.length - 1];
            mck128.process(es, 1, ds, 0, ds.length);
            assertTrue(Utils.arraysEquals(ds, 0, ps, 1, ds.length));
        }
    }
}
