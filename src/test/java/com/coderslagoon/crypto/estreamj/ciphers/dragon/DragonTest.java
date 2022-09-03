package com.coderslagoon.crypto.estreamj.ciphers.dragon;

import java.util.Arrays;

import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.ICipher;
import com.coderslagoon.crypto.estreamj.framework.Utils;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class DragonTest {
    // NOTE: the Dragon reference source code is messy regarding byte ordering
    //       and how things should be interpreted when reading a test vector;
    //       thus adjustments had to be made to get a match; if this algorithm
    //       ever becomes the finalist then the creators for sure will have some
    //       extra explaining to do :)

    ///////////////////////////////////////////////////////////////////////////

    static final String[] VECTOR_128_1 = {
        "cc00001111222233334444555566667777",
        "cc00001111222233334444555566667777",
        "cc99B3AA14B63BD02FE14358A454950425F4B0D3FD8BA69178E0392938A718C1652" +
        "E3BEB1E11613D589EABB9F543A1C51C73C1F2279D1CAEA85C55F539BAFD3C59ECAC" +
        "88BD17EB1C9DA28DD63E9093C9133032D9183A9B33BC2933A79D7566982720EF300" +
        "4C53B02537A1BE79629F8D9A38DC1FD31ED9D1100B07DFFB1AC75EB31"
    };

    @Test
    public void test128() throws ESJException {
        byte[] key, nonce, ks, es;
        Dragon drg;

        drg = new Dragon(false);

        key   = Utils.hexStrToBytes(VECTOR_128_1[0]);
        nonce = Utils.hexStrToBytes(VECTOR_128_1[1]);
        ks    = Utils.hexStrToBytes(VECTOR_128_1[2]);

        // NOTE: we need to swap because the printed vectors are not bytes, but
        //       just dumped 32bit words, so they appear in big endian; however
        //       we assume LE since the rest of the C code does it this way

        Utils.swapByteOrder32(key, 1, key.length - 1);
        Utils.swapByteOrder32(nonce, 1, nonce.length - 1);
        Utils.swapByteOrder32(ks, 1, ks.length - 1);

        assertEquals(drg.getKeySize(), key.length - 1);
        assertEquals(drg.getNonceSize(), nonce.length - 1);
        assertEquals(128, ks.length - 1);

        drg.setupKey(ICipher.MODE_ENCRYPT, key, 1);
        drg.setupNonce(nonce, 1);

        es = new byte[ks.length];
        Arrays.fill(es, (byte)0xcc);
        drg.process(new byte[ks.length], 1, es, 1, es.length - 1);

        assertEquals((byte)0xcc, es[0]);
        assertTrue(Utils.arraysEquals(es, 1, ks, 1, ks.length - 1));
    }


    ///////////////////////////////////////////////////////////////////////////

    static final String[] VECTOR_256_1 = {
        "cc0000111122223333444455556666777788889999AAAABBBBCCCCDDDDEEEEFFFF",
        "cc0000111122223333444455556666777788889999AAAABBBBCCCCDDDDEEEEFFFF",
        "cc" +
        "BC020767DC48DAE314778D8C927E8B32E086C6CDE593C008600C9D47A488F622" +
        "3A2B94D6B853D64427E93362ABB8BA21751CAAF7BD3165952A37FC1EA3F12FE2" +
        "5C133BA74C15CE4B3542FDF893DAA751F571025649795D5431914EBA0DE2C2A7" +
        "8013D29B56D4A0283EB6F3127644ECFE38B9CA111924FBC94A0A30F2AFFF5FE0"
    };

    @Test
    public void test256() throws ESJException {
        byte[] key, nonce, ks, es;
        Dragon drg;

        drg = new Dragon(true);

        key   = Utils.hexStrToBytes(VECTOR_256_1[0]);
        nonce = Utils.hexStrToBytes(VECTOR_256_1[1]);
        ks    = Utils.hexStrToBytes(VECTOR_256_1[2]);

        Utils.swapByteOrder32(key, 1, key.length - 1);
        Utils.swapByteOrder32(nonce, 1, nonce.length - 1);
        Utils.swapByteOrder32(ks, 1, ks.length - 1);

        assertEquals(drg.getKeySize(), key.length - 1);
        assertEquals(drg.getNonceSize(), nonce.length - 1);
        assertEquals(128, ks.length - 1);

        drg.setupKey(ICipher.MODE_ENCRYPT, key, 1);
        drg.setupNonce(nonce, 1);

        es = new byte[ks.length];
        Arrays.fill(es, (byte)0xcc);
        drg.process(new byte[ks.length], 1, es, 1, es.length - 1);

        assertEquals((byte)0xcc, es[0]);
        assertTrue(Utils.arraysEquals(es, 1, ks, 1, ks.length - 1));
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Test different data sizes to check for proper unaligned data handling.
     */
    @Test
    public void testEncDec() throws ESJException {
        int count, type;
        byte[] ptxt, etxt, dtxt, badKey;
        Dragon drg;

        for (type = 0; type < 2; type++) {
            drg = new Dragon(0 == type);

            for (count = 0; count <= 267; count++) {
                drg.setupKey(ICipher.MODE_ENCRYPT,
                        new byte[drg.getKeySize()], 0);
                drg.setupNonce(new byte[drg.getNonceSize()], 0);

                ptxt = new byte[count];
                Utils.fillPattern123(ptxt, 0, ptxt.length);
                etxt = new byte[count];
                drg.process(ptxt, 0, etxt, 0, ptxt.length);

                drg.setupKey(ICipher.MODE_DECRYPT,
                        new byte[drg.getKeySize()], 0);
                drg.setupNonce(new byte[drg.getNonceSize()], 0);

                dtxt = new byte[count];
                drg.process(etxt, 0, dtxt, 0, dtxt.length);
                assertTrue(Utils.checkPattern123(dtxt, 0, dtxt.length));

                if (0 < count) {
                    badKey = new byte[drg.getKeySize()];
                    badKey[5] = (byte)0xff;
                    drg.setupKey(ICipher.MODE_DECRYPT, badKey, 0);
                    drg.setupNonce(new byte[drg.getNonceSize()], 0);
                    drg.process(etxt, 0, dtxt, 0, dtxt.length);
                    assertFalse(Utils.checkPattern123(dtxt, 0, dtxt.length));
                }
            }
        }
    }
}
