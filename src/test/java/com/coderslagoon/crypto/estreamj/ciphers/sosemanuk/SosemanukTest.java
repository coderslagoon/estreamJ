package com.coderslagoon.crypto.estreamj.ciphers.sosemanuk;

import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.ICipher;
import com.coderslagoon.crypto.estreamj.framework.Utils;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SosemanukTest {
    static final String[] TEST_VECTOR_1 = {
        "00112233445566778899AABBCCDDEEFF",     // key
        "8899AABBCCDDEEFF0011223344556677",     // nonce
        "FA61DBEB71178131A77C714BD2EABF4E" +    // keystream (160 bytes)
        "1394207A25698AA1308F2F063A0F7606" +
        "04CF67569BA59A3DFAD7F00145C78D29" +
        "C5FFE5F964950486424451952C84039D" +
        "234D9C37EECBBCA1EBFB0DD16EA1194A" +
        "6AFC1A460E33E33FE8D55C48977079C6" +
        "87810D74FEDDEE1B3986218FB1E1C176" +
        "5E4DF64D7F6911C19A270C59C74B2446" +
        "1717F86CE3B11808FACD4F2E714168DA" +
        "44CF6360D54DDA2241BCB79401A4EDCC"
    };

    @Test
    public void test1() throws ESJException {
        Sosemanuk sm;
        byte[] key, nonce, ktxt, ptxt, ctxt, dtxt;

        sm = new Sosemanuk();

        key = Utils.hexStrToBytes(TEST_VECTOR_1[0]);
        assertEquals(sm.getKeySize(), key.length);

        nonce = Utils.hexStrToBytes(TEST_VECTOR_1[1]);
        assertEquals(sm.getNonceSize(), nonce.length);
        ktxt = Utils.hexStrToBytes(TEST_VECTOR_1[2]);
        assertEquals(160, ktxt.length);

        sm.setupKey(ICipher.MODE_ENCRYPT, key, 0);
        sm.setupNonce(nonce, 0);

        ptxt = new byte[ktxt.length];
        ctxt = new byte[ktxt.length];
        sm.process(ptxt, 0, ctxt, 0, ctxt.length);
        assertTrue(Utils.arraysEquals(ctxt, 0, ktxt, 0, ktxt.length));

        sm.reset();
        sm.setupKey(ICipher.MODE_DECRYPT, key, 0);
        sm.setupNonce(nonce, 0);
        dtxt = new byte[ctxt.length];
        sm.process(ctxt, 0, dtxt, 0, dtxt.length);
        assertTrue(Utils.arraysEquals(dtxt, 0, ptxt, 0, ptxt.length));
    }
}
