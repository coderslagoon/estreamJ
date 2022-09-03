package com.coderslagoon.crypto.estreamj.ciphers.phelix;

import java.util.Arrays;

import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.ICipher;
import com.coderslagoon.crypto.estreamj.framework.Utils;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Test case transformed from the original PhelixJ package.
 */
public class PhelixTest {
    static final byte[] REF_PTXT_0 = new byte[] { 0,0,0,0,0,0,0,0,0,0 };
    static final byte[] REF_CTXT_0 = new byte[] {
        (byte)0xd5, 0x2d, 0x45, (byte)0xc6, 0x05, (byte)0xfd, 0x7a, 0x67, 0x74,
        (byte)0x8d };
    static final byte[] REF_MAC_0 = new byte[] {
        (byte)0xef, 0x7b, (byte)0xfe, 0x7a, (byte)0xeb, (byte)0xdc, 0x1a,
        (byte)0x8b, 0x43, 0x36, 0x2f, 0x28, (byte)0x93, (byte)0x80, 0x0d,
        (byte)0xbc };

    @Test
    public void testZeroVector() throws ESJException {
        byte[] ctxt, ptxt, mac, mac2;
        Phelix phx;

        phx = new Phelix(Phelix.PHELIX_MAC_SIZE);

        // we have to use setupKeyEx() since the key sizes vary here
        phx.setupKeyEx(ICipher.MODE_ENCRYPT, new byte[0], 0, 0);
        phx.setupNonce(new byte[phx.getNonceSize()], 0);

        assertEquals(10, REF_PTXT_0.length);

        ctxt = Utils.makeOutputBuffer(REF_PTXT_0.length, 0);

        phx.process(REF_PTXT_0, 0, ctxt, 0, REF_PTXT_0.length);

        mac = new byte[phx.getMacSize()];

        phx.finalize(mac, 0);

        assertTrue(Arrays.equals(ctxt, REF_CTXT_0));
        assertTrue(Arrays.equals(mac, REF_MAC_0));

        // test decryption and MAC recomputation
        phx = new Phelix(Phelix.PHELIX_MAC_SIZE);

        phx.setupKeyEx(ICipher.MODE_DECRYPT, new byte[0], 0, 0);
        phx.setupNonce(new byte[phx.getNonceSize()], 0);

        ptxt = Utils.makeOutputBuffer(REF_PTXT_0.length, 0);

        phx.process(ctxt, 0, ptxt, 0, ctxt.length);

        mac2 = new byte[phx.getMacSize()];

        phx.finalize(mac2, 0);

        assertTrue(Arrays.equals(ptxt, REF_PTXT_0));
        assertTrue(Arrays.equals(mac2, mac));
    }

    static final byte[] REF_KEY_1 = new byte[] {
        0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0,
        4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0
    };
    static final byte[] REF_NONCE_1 = new byte[] {
        0, 0, 0, 1, 1, 0, 0, 1, 2, 0, 0, 1, 3, 0, 0, 1
    };
    static final byte[] REF_PTXT_1 = new byte[] {
        0, 1, 2, 3, 1, 2, 3, 4, 2, 3, 4, 5, 3, 4, 5, 6,
        4, 5, 6, 7, 5, 6, 7, 8, 6, 7, 8, 9, 7, 8, 9, 10
    };
    static final byte[] REF_CTXT_1 = new byte[] {
        (byte)0xb5,(byte)0xfc,(byte)0x4b,(byte)0xf5,(byte)0xbc,(byte)0x64,
        (byte)0x0a,(byte)0x56,(byte)0x00,(byte)0x3d,(byte)0x59,(byte)0x6d,
        (byte)0x33,(byte)0x4b,(byte)0xa5,(byte)0x94,(byte)0xa5,(byte)0x48,
        (byte)0x7b,(byte)0x4e,(byte)0x30,(byte)0x8e,(byte)0xdb,(byte)0x05,
        (byte)0xa7,(byte)0xd6,(byte)0x2f,(byte)0x23,(byte)0x45,(byte)0x14,
        (byte)0x02,(byte)0x4a
    };
    static final byte[] REF_MAC_1 = new byte[] {
        (byte)0xdb,(byte)0x0c,(byte)0x22,(byte)0xc4,(byte)0x66,(byte)0xbd,
        (byte)0xcd,(byte)0xe4,(byte)0xe3,(byte)0x29,(byte)0x03,(byte)0xf7,
        (byte)0x9a,(byte)0xe5,(byte)0x42,(byte)0xd1
    };

    // (testing proper offset handling by prepending a 0xcc to each array)
    static final byte[] REF_KEY_2 = new byte[] {
        (byte)0xcc,(byte)0x09,(byte)0x07,(byte)0x05,(byte)0x03,(byte)0x01,
        (byte)0,(byte)0,(byte)0   // (we need 3 zeros of padding here!)
    };
    static final byte[] REF_AAD_2 = new byte[] {
        (byte)0xcc,(byte)0x00,(byte)0x02,(byte)0x04,(byte)0x06,(byte)0x01,
        (byte)0x03,(byte)0x05,(byte)0x07,(byte)0x08
    };
    static final byte[] REF_NONCE_2 = new byte[] {
        (byte)0xcc,(byte)0x08,(byte)0x07,(byte)0x06,(byte)0x05,(byte)0x04,
        (byte)0x03,(byte)0x02,(byte)0x01,(byte)0x00,(byte)0x01,(byte)0x02,
        (byte)0x03,(byte)0x04,(byte)0x05,(byte)0x06,(byte)0x07
    };
    static final byte[] REF_PTXT_2 = new byte[] {
        (byte)0xcc,(byte)0x00,(byte)0x01,(byte)0x02,(byte)0x03,(byte)0x01,
        (byte)0x02,(byte)0x03,(byte)0x04,(byte)0x02,(byte)0x03,(byte)0x04,
        (byte)0x05,(byte)0xff
    };
    static final byte[] REF_CTXT_2 = new byte[] {
        (byte)0xcc,(byte)0xf1,(byte)0x0d,(byte)0x3e,(byte)0x06,(byte)0x7a,
        (byte)0x32,(byte)0xb1,(byte)0xbe,(byte)0xda,(byte)0xa5,(byte)0x89,
        (byte)0x8b,(byte)0xde
    };
    static final byte[] REF_MAC_2 = new byte[] {
        (byte)0xcc,(byte)0x60,(byte)0xa2,(byte)0x31,(byte)0xc1,(byte)0xc9,
        (byte)0xf5,(byte)0xe4,(byte)0xef,(byte)0x40,(byte)0xaa,(byte)0x0a,
        (byte)0x1c
    };

    @Test
    public void testMoreVectors() throws ESJException {
        byte[] ptxt, ctxt, mac, mac2;
        Phelix phx;

        phx = new Phelix(Phelix.PHELIX_MAC_SIZE);

        phx.setupKeyEx(ICipher.MODE_ENCRYPT, REF_KEY_1, 0, REF_KEY_1.length << 3);
        phx.setupNonce(REF_NONCE_1, 0);

        ctxt = Utils.makeOutputBuffer(REF_PTXT_1.length, 0);

        phx.process(REF_PTXT_1, 0, ctxt, 0, REF_PTXT_1.length);

        mac = new byte[phx.getMacSize()];
        phx.finalize(mac, 0);

        assertTrue(Arrays.equals(ctxt, REF_CTXT_1));
        assertTrue(Arrays.equals(mac, REF_MAC_1));

        phx = new Phelix(Phelix.PHELIX_MAC_SIZE);

        phx.setupKeyEx(ICipher.MODE_DECRYPT, REF_KEY_1, 0, REF_KEY_1.length << 3);
        phx.setupNonce(REF_NONCE_1, 0);

        ptxt = Utils.makeOutputBuffer(REF_PTXT_1.length, 0);

        phx.process(ctxt, 0, ptxt, 0, ctxt.length);

        mac2 = new byte[Phelix.PHELIX_MAC_SIZE >> 3];
        phx.finalize(mac2, 0);

        assertTrue(Arrays.equals(ptxt, REF_PTXT_1));
        assertTrue(Arrays.equals(mac, mac2));

        phx = new Phelix(Phelix.PHELIX_MAC_SIZE_96);

        phx.setupKeyEx(ICipher.MODE_ENCRYPT, REF_KEY_2, 1, 40);
        phx.setupNonce(REF_NONCE_2, 1);

        ctxt = Utils.makeOutputBuffer(REF_PTXT_2.length - 1, 1);

        phx.processAAD(REF_AAD_2, 1, REF_AAD_2.length - 1);
        phx.process(REF_PTXT_2, 1, ctxt, 1, REF_PTXT_2.length - 1);

        mac = new byte[1 + phx.getMacSize()];
        phx.finalize(mac, 1);

        assertTrue(Utils.arraysEquals(ctxt, 1, REF_CTXT_2, 1, REF_CTXT_2.length - 1));
        assertTrue(Utils.arraysEquals(mac, 1, REF_MAC_2, 1, REF_MAC_2.length - 1));

        phx.reset();    // MAC size hasn't change, so we can reuse the instance

        phx.setupKeyEx(ICipher.MODE_DECRYPT, REF_KEY_2, 1, 40);
        phx.setupNonce(REF_NONCE_2, 1);

        ptxt = Utils.makeOutputBuffer(REF_PTXT_2.length - 1, 1);

        phx.processAAD(REF_AAD_2, 1, REF_AAD_2.length - 1);
        phx.process(ctxt, 1, ptxt, 1, ctxt.length - 1);

        mac2 = new byte[phx.getMacSize() + 1];
        phx.finalize(mac2, 1);

        assertTrue(Utils.arraysEquals(ptxt, 1, REF_PTXT_2, 1, REF_PTXT_2.length - 1));
        assertTrue(Utils.arraysEquals(mac2, 1, mac, 1, mac2.length - 1));
    }

    static final byte[] REF_KEY_3 = {
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
        (byte)0xff,(byte)0xfe,(byte)0xfd,(byte)0xfc,(byte)0xfb,(byte)0xfa,
        (byte)0xf9,(byte)0xf8,(byte)0xf7,(byte)0xf6,(byte)0xf5,(byte)0xf4,
        (byte)0xf3,(byte)0xf2,(byte)0xf1,(byte)0xf0
    };
    static final byte[] REF_NONCE_3 = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        (byte)0xf8,(byte)0xf9,(byte)0xfa,(byte)0xfb,(byte)0xfc,(byte)0xfd,
        (byte)0xfe,(byte)0xff
    };
    static final byte[] REF_REF_MAC_3 = new byte[] {
        (byte)0xab,(byte)0xda,0x1b,(byte)0xc6,(byte)0xc9,(byte)0x92,0x13,
        0x42,0x53,0x77,0x01,0x4b,(byte)0xc6,(byte)0xe4,0x67,0x44
    };

    @Test
    public void testOneMillionAs() throws ESJException {
        byte[] tas, mac;
        Phelix phx;


        tas = new byte[1000];
        Arrays.fill(tas, (byte)'a');

        phx = new Phelix(Phelix.PHELIX_MAC_SIZE);
        phx.reset();

        phx.setupKeyEx(ICipher.MODE_ENCRYPT,
                REF_KEY_3, 0, REF_KEY_3.length << 3);
        phx.setupNonce(REF_NONCE_3, 0);

        for (int i = 0; i < 1000; i++) {
            phx.processAAD(tas, 0, tas.length);
        }

        mac = new byte[phx.getMacSize()];
        phx.finalize(mac, 0);

        assertTrue(Arrays.equals(mac, REF_REF_MAC_3));
    }
}
