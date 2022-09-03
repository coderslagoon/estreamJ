package com.coderslagoon.crypto.estreamj.ciphers.aes;

import java.util.Arrays;

import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.ICipher;
import com.coderslagoon.crypto.estreamj.framework.Utils;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class AESTest {
    static final String[] VECTOR_CORE_KEY128_1 = {
        "2b7e151628aed2a6abf7158809cf4f3c",     // key
        "3243f6a8885a308d313198a2e0370734",     // ptxt
        "3925841d02dc09fbdc118597196a0b32"      // ctxt
    };

    @Test
    public void testCore() {
        byte[] key, ptxt, etxt, dtxt, ctxt;
        AES aes;

        for (int type = 0; type < 2; type++) {
            if (0 == type) aes = new AESLean();
            else           aes = new AESMean();

            key = Utils.hexStrToBytes(VECTOR_CORE_KEY128_1[0]);
            assertEquals(16, key.length);

            aes.init(true, key, 0, key.length);

            ptxt = Utils.hexStrToBytes(VECTOR_CORE_KEY128_1[1]);
            assertEquals(16, ptxt.length);

            etxt = new byte[ptxt.length];
            aes.processBlock(ptxt, 0, etxt, 0);

            ctxt = Utils.hexStrToBytes(VECTOR_CORE_KEY128_1[2]);
            assertEquals(16, ctxt.length);

            assertTrue(Utils.arraysEquals(ctxt, 0, etxt, 0, etxt.length));

            // test decryption
            aes.init(false, key, 0, key.length);

            dtxt = new byte[18];
            dtxt[0] = (byte)0xcc;
            dtxt[17] = (byte)0xcc;

            aes.processBlock(etxt, 0, dtxt, 1);

            assertEquals((byte)0xcc, dtxt[0]);
            assertEquals((byte)0xcc, dtxt[17]);
            assertTrue(Utils.arraysEquals(dtxt, 1, ptxt, 0, ptxt.length));
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    static final String[] VECTOR1 = new String[] {
        "80000000000000000000000000000000",
        "00000000000000000000000000000000",
        "0EDD33D3C621E546455BD8BA1418BEC8" +
        "E5350DE3B26A17ED1D235EA8C204A939" +
        "D8134F2CC7059A383340C7C8F8B30A1E" +
        "2FF709568A15FF6E402A79E90057A34F" +
        "ADF5DD42C5CDE667D6D4BB12D2D85CD1" +
        "C472605E0B2FC670F603D94ACCED3912" +
        "3037D06E5E4B884195F212EE76D39C76" +
        "D2B5544F179A0EAE3E666F82801BBD7C" +
        "69A06558F49E7AFD2B886E910B238610" +
        "78E09559E48B6B3A2A127D3CC277AE69" +
        "29AD6C1296C168634B54FA42A4F3CCC0" +
        "54B520FD85F8808CB75C868E55C5ADCD" +
        "27EEDA49847DA860129F639F2ED65D27" +
        "C03C53DE6543C076AADF213740A758C8" +
        "74648DE78B9BA24D413680096B151F82" +
        "8599FBD4E10F5F0B0460BC58837B097A"
    };

    static final String[] VECTOR2 = new String[] {
        "0F62B5085BAE0154A7FA4DA0F34699EC",
        "288FF65DC42B92F960C72E95FC63CA31",
        "A7124D7BBFB4A1DC10D26C9FB51103CB" +
        "3EE0AE5115714D196BAED193F28BF6FA" +
        "CAAB4154D44DE8E992951D7B395A7633" +
        "7282FD58BD2F063002179F5016696C00" +
        "8504FC8118CE9DD404DCC57461A8BE8C" +
        "1DB017B5B36C87054605A2150F2D640F" +
        "029F8721CC39E8C686D94C18E9317F37" +
        "9FCD2439C2D5A002A9640339F49AB578" +
        "D9B1838BA40A4B8CC09BB7BD6A682C78" +
        "996012BCF5665AA9238AB97E84E2D4E7" +
        "4EC8D6E6EF4158B85A420241F41F0EC7" +
        "131574C063C33015DFD42E8CB33DCC2E" +
        "24F3E4C72781F0E5D604A3C7EEEA6154" +
        "2C5130256900229C34A2F9E4A417F028" +
        "1F42E21DC32AE5283671901ECDB71CA9" +
        "909EF539D6487DCF0FED28AE646B78ED"
    };

    @Test
    public void testVectors() throws ESJException {
        int lean;
        byte[] key, iv, ctxt, ptxt, dtxt;

        for (lean = 0; lean < 2; lean++) {
            AESCTR aes = new AESCTR(1 == lean);

            assertEquals(3, VECTOR1.length);

            key  = Utils.hexStrToBytes(VECTOR1[0]);
            iv   = Utils.hexStrToBytes(VECTOR1[1]);
            ctxt = Utils.hexStrToBytes(VECTOR1[2]);

            assertEquals(aes.getKeySize()  , key .length);
            assertEquals(aes.getNonceSize(), iv  .length);
            assertEquals(256               , ctxt.length);

            aes.reset();
            aes.setupKey(ICipher.MODE_ENCRYPT, key, 0);
            aes.setupNonce(iv, 0);

            ptxt = new byte[512];
            Arrays.fill(ptxt, (byte)0);

            aes.process(ptxt, 0, ptxt, 0, ptxt.length);

            /*
            Utils.hexDump(
                    new java.io.ByteArrayInputStream(ptxt),
                    System.out,
                    512,
                    16);
            */

            assertTrue(Utils.arraysEquals(ptxt, 0  , ctxt,   0, 64));
            assertTrue(Utils.arraysEquals(ptxt, 192, ctxt,  64, 64));
            assertTrue(Utils.arraysEquals(ptxt, 256, ctxt, 128, 64));
            assertTrue(Utils.arraysEquals(ptxt, 448, ctxt, 192, 64));

            // test decryption
            aes.reset();
            aes.setupKey(ICipher.MODE_DECRYPT, key, 0);
            aes.setupNonce(iv, 0);
            dtxt = new byte[512];
            aes.process(ptxt, 0, dtxt, 0, dtxt.length);
            assertTrue(Utils.arraysEquals(new byte[512], 0, dtxt, 0, 512));

            ///////////////////////////////////////////////////////////////////////

            assertEquals(3, VECTOR2.length);

            key  = Utils.hexStrToBytes(VECTOR2[0]);
            iv   = Utils.hexStrToBytes(VECTOR2[1]);
            ctxt = Utils.hexStrToBytes(VECTOR2[2]);

            assertEquals(aes.getKeySize()  , key .length);
            assertEquals(aes.getNonceSize(), iv  .length);
            assertEquals(256               , ctxt.length);

            aes = new AESCTR(1 == lean);
            aes.setupKey(ICipher.MODE_ENCRYPT, key, 0);
            aes.setupNonce(iv, 0);

            ptxt = new byte[131072];
            Arrays.fill(ptxt, (byte)0);

            aes.process(ptxt, 0, ptxt, 0, ptxt.length);

            assertTrue(Utils.arraysEquals(ptxt,      0, ctxt,   0, 64));
            assertTrue(Utils.arraysEquals(ptxt,  65472, ctxt,  64, 64));
            assertTrue(Utils.arraysEquals(ptxt,  65536, ctxt, 128, 64));
            assertTrue(Utils.arraysEquals(ptxt, 131008, ctxt, 192, 64));
        }
    }
}
