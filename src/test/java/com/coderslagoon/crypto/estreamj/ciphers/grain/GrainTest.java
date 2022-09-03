package com.coderslagoon.crypto.estreamj.ciphers.grain;

import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.ICipher;
import com.coderslagoon.crypto.estreamj.framework.Utils;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class GrainTest {
    static final String[][] TEST_VECTORS_P2 = {
        {
            "cc00000000000000000000",
            "cc0000000000000000",
            "ccdee931cf1662a72f77d0"
        }, {
            "cc0123456789abcdef1234",
            "cc0123456789abcdef",
            "cc7f362bd3f7abae203664"
        }
    };

    static final String[][] TEST_VECTORS_128 = {
        {
            "cc00000000000000000000000000000000",
            "cc000000000000000000000000",
            "ccf09b7bf7d7f6b5c2de2ffc73ac21397f"
        }, {
            "cc0123456789abcdef123456789abcdef0",
            "cc0123456789abcdef12345678",
            "ccafb5babfa8de896b4b9c6acaf7c4fbfd"
        }
    };

    @Test
    public void test0() throws ESJException {
        GrainRefNoopt grain;
        byte[] key, nonce, ktxt, etxt, ztxt;

        for (int type = 0; type < 2; type++) {
            for (String[] tv : 0 == type ? TEST_VECTORS_P2 : TEST_VECTORS_128) {
                grain = 0 == type ? new GrainP2Noopt() : new Grain128Noopt();

                key = Utils.hexStrToBytes(tv[0]);
                assertEquals(grain.getKeySize(), key.length - 1);
                nonce = Utils.hexStrToBytes(tv[1]);
                assertEquals(grain.getNonceSize(), nonce.length - 1);
                ktxt = Utils.hexStrToBytes(tv[2]);
                assertEquals((0 == type ? 10 : 16), ktxt.length - 1);

                grain.setupKey(ICipher.MODE_ENCRYPT, key, 1);
                grain.setupNonce(nonce, 1);

                etxt = new byte[ktxt.length];
                etxt[0] = (byte)0xcc;
                grain.process(etxt, 1, etxt, 1, etxt.length - 1);
                assertTrue(Utils.arraysEquals(etxt, 0, ktxt, 0, ktxt.length));

                grain.reset();
                grain.setupKey(ICipher.MODE_DECRYPT, key, 1);
                grain.setupNonce(nonce, 1);
                etxt[0] = (byte)0xdd;
                grain.process(etxt, 1, etxt, 1, etxt.length - 1);
                ztxt = new byte[etxt.length];
                ztxt[0] = (byte)0xdd;
                assertTrue(Utils.arraysEquals(ztxt, 0, etxt, 0, etxt.length));
            }
        }
    }
}
