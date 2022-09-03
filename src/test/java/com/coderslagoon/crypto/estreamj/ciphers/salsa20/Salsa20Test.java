package com.coderslagoon.crypto.estreamj.ciphers.salsa20;

import java.util.Arrays;

import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.ICipher;
import com.coderslagoon.crypto.estreamj.framework.Utils;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class Salsa20Test {
    static final String[] VECTOR1 = new String[] {
        "80000000000000000000000000000000" +    // key
        "00000000000000000000000000000000",
        "0000000000000000",                     // IV
        "E3BE8FDD8BECA2E3EA8EF9475B29A6E7" +
        "003951E1097A5C38D23B7A5FAD9F6844" +
        "B22C97559E2723C7CBBD3FE4FC8D9A07" +
        "44652A83E72A9C461876AF4D7EF1A117" +
        "57BE81F47B17D9AE7C4FF15429A73E10" +
        "ACF250ED3A90A93C711308A74C6216A9" +
        "ED84CD126DA7F28E8ABF8BB63517E1CA" +
        "98E712F4FB2E1A6AED9FDC73291FAA17" +
        "958211C4BA2EBD5838C635EDB81F513A" +
        "91A294E194F1C039AEEC657DCE40AA7E" +
        "7C0AF57CACEFA40C9F14B71A4B3456A6" +
        "3E162EC7D8D10B8FFB1810D71001B618" +
        "696AFCFD0CDDCC83C7E77F11A649D79A" +
        "CDC3354E9635FF137E929933A0BD6F53" +
        "77EFA105A3A4266B7C0D089D08F1E855" +
        "CC32B15B93784A36E56A76CC64BC8477"
    };

    static final String[] VECTOR2 = new String[] {
        "0F62B5085BAE0154A7FA4DA0F34699EC" +
        "3F92E5388BDE3184D72A7DD02376C91C",
        "288FF65DC42B92F9",
        "5E5E71F90199340304ABB22A37B6625B" +
        "F883FB89CE3B21F54A10B81066EF87DA" +
        "30B77699AA7379DA595C77DD59542DA2" +
        "08E5954F89E40EB7AA80A84A6176663F" +
        "2DA2174BD150A1DFEC1796E921E9D6E2" +
        "4ECF0209BCBEA4F98370FCE629056F64" +
        "917283436E2D3F45556225307D5CC5A5" +
        "65325D8993B37F1654195C240BF75B16" +
        "ABF39A210EEE89598B7133377056C2FE" +
        "F42DA731327563FB67C7BEDB27F38C7C" +
        "5A3FC2183A4C6B277F901152472C6B2A" +
        "BCF5E34CBE315E81FD3D180B5D66CB6C" +
        "1BA89DBD3F98839728F56791D5B7CE23" +
        "5036DE843CCCAB0390B8B5862F1E4596" +
        "AE8A16FB23DA997F371F4E0AACC26DB8" +
        "EB314ED470B1AF6B9F8D69DD79A9D750"
    };

    @Test
    public void testVectors() throws ESJException {
        byte[] key, iv, ctxt, ptxt;
        Salsa20 sat = new Salsa20();


        // make sure the test vector itself is in good shape
        assertEquals(3, VECTOR1.length);

        key  = Utils.hexStrToBytes(VECTOR1[0]);
        iv   = Utils.hexStrToBytes(VECTOR1[1]);
        ctxt = Utils.hexStrToBytes(VECTOR1[2]);

        assertEquals(sat.getKeySize()  , key .length);
        assertEquals(sat.getNonceSize(), iv  .length);
        assertEquals(256               , ctxt.length);

        sat.setupKey(ICipher.MODE_ENCRYPT, key, 0);
        sat.setupNonce(iv, 0);

        ptxt = new byte[512];
        Arrays.fill(ptxt, (byte)0);

        sat.process(ptxt, 0, ptxt, 0, ptxt.length);

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

        sat.reset();
        Arrays.fill(ptxt, (byte)0);
        sat.process(ptxt, 0, ptxt, 0, ptxt.length);
        assertTrue(Utils.arraysEquals(ptxt, 0, ctxt, 0, 64));

        ///////////////////////////////////////////////////////////////////////

        assertEquals(3, VECTOR2.length);

        key  = Utils.hexStrToBytes(VECTOR2[0]);
        iv   = Utils.hexStrToBytes(VECTOR2[1]);
        ctxt = Utils.hexStrToBytes(VECTOR2[2]);

        assertEquals(sat.getKeySize()  , key .length);
        assertEquals(sat.getNonceSize(), iv  .length);
        assertEquals(256               , ctxt.length);

        sat.setupKey(ICipher.MODE_DECRYPT, key, 0);
        sat.setupNonce(iv, 0);

        ptxt = new byte[131072];
        Arrays.fill(ptxt, (byte)0);

        sat.process(ptxt, 0, ptxt, 0, ptxt.length);

        assertTrue(Utils.arraysEquals(ptxt,      0, ctxt,   0, 64));
        assertTrue(Utils.arraysEquals(ptxt,  65472, ctxt,  64, 64));
        assertTrue(Utils.arraysEquals(ptxt,  65536, ctxt, 128, 64));
        assertTrue(Utils.arraysEquals(ptxt, 131008, ctxt, 192, 64));
    }
}
