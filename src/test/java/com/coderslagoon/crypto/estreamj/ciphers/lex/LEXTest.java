package com.coderslagoon.crypto.estreamj.ciphers.lex;

import java.util.Arrays;

import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.ICipher;
import com.coderslagoon.crypto.estreamj.framework.Utils;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class LEXTest {
    /**
     * The original C code has at least one bug in LEX-ALG-FST.C at the
     * rijndaelEncrypt() function, where pt got read out with wrong offsets.
     * The vectors below are unofficial, but from corrected code. Another issue
     * was the "hardcoded" byte ordering. Run on x86 and assuming that this is
     * the official way on how it's supposed to be.
     */
    static final String[][] TEST_VECTORS = {
        {
            "000102030405060708090a0b0c0d0e0f",
            "00000000000000000000000000000000",
            "5fa9bd9450cf0c95aa3972c852c34c83a73fe9a241b5825ff80bbed0ffc3ae684f20c7233bc40907"

        }, {
            "000102030405060708090a0b0c0d0e0f",
            "01000000000000000000000000000000",
            "a4a543954e1b11c5707e3f3e4b9a7bc083cd0f53d186430d39615c42b80de8253a884c3d2e453efe"

        }, {
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "2bb695d48d659ffe86e833ed324400a400258e630bf04b81c6af2578b9b707a658b4aadc45f1e51a"
        },
    };

    @Test
    public void test1() throws ESJException {
        for (String[] tv : TEST_VECTORS) {
            byte[] key, nonce, rtxt, ptxt, etxt, dtxt;

            LEX lex = new LEX();

            key = Utils.hexStrToBytes(tv[0]);
            nonce = Utils.hexStrToBytes(tv[1]);
            rtxt = Utils.hexStrToBytes(tv[2]);

            assertEquals(lex.getKeySize(), key.length);
            assertEquals(lex.getNonceSize(), nonce.length);
            assertEquals(0, rtxt.length % lex.getWordSize());
            assertEquals(40, rtxt.length);

            lex.setupKey(ICipher.MODE_ENCRYPT, key, 0);
            lex.setupNonce(nonce, 0);

            ptxt = new byte[rtxt.length];
            etxt = new byte[rtxt.length];
            lex.process(ptxt, 0, etxt, 0, ptxt.length);
            assertTrue(Utils.arraysEquals(etxt, 0, rtxt, 0, rtxt.length));

            lex.reset();
            lex.setupKey(ICipher.MODE_DECRYPT, key, 0);
            lex.setupNonce(nonce, 0);

            dtxt = new byte[rtxt.length];
            Arrays.fill(dtxt, (byte)0xcc);
            lex.process(ptxt, 0, dtxt, 0, ptxt.length);
        }
    }

    static final String[][] TEST_VECTORS_2 = {
        {
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "2bb695d48d659ffe86e833ed324400a400258e630bf04b81c6af2578b9b707a658b4aadc45f1e51a" +
            "1739161ec22b19aafd5ea20227606f057c473383934a7443dd9d0854433f7e22feed28348c6c34ae" +
            "e26072f4e379320728d50007f63996cf6988a32299dc1d5edd9cd9e1feddaceb66dd93babc8b4607" +
            "73cd18be9d8ef1f6fc78cce0241217f3234132750d76f2333d75d7c3cd739c1f8f9dd4216a6b99b6"
        }, {
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "2bb695d48d659ffe86e833ed324400a400258e630bf04b81c6af2578b9b707a658b4aadc45f1e51a1739161ec22b"
        }, {
            "baadf00dcafebabeccccfea9000102ff",
            "fedcba98765432100001237899aabbff",
            "dee753c38aa5ae7167167b6e46e939aa8f259c5ebb5a059814c536f7530a575bd7c10cd0bf22b91e9d"
        }
    };

    @Test
    public void test2() throws ESJException {
        for (String[] tv : TEST_VECTORS_2) {
            byte[] key, nonce, rtxt, ptxt, etxt, dtxt;

            LEX lex = new LEX();

            key = Utils.hexStrToBytes(tv[0]);
            nonce = Utils.hexStrToBytes(tv[1]);
            rtxt = Utils.hexStrToBytes(tv[2]);

            assertEquals(lex.getKeySize(), key.length);
            assertEquals(lex.getNonceSize(), nonce.length);

            lex.setupKey(ICipher.MODE_ENCRYPT, key, 0);
            lex.setupNonce(nonce, 0);

            ptxt = new byte[rtxt.length];
            etxt = new byte[rtxt.length];
            lex.process(ptxt, 0, etxt, 0, ptxt.length);
            assertTrue(Utils.arraysEquals(etxt, 0, rtxt, 0, rtxt.length));

            lex.reset();
            lex.setupKey(ICipher.MODE_DECRYPT, key, 0);
            lex.setupNonce(nonce, 0);

            dtxt = new byte[rtxt.length];
            Arrays.fill(dtxt, (byte)0xcc);
            lex.process(ptxt, 0, dtxt, 0, ptxt.length);
        }
    }
}
