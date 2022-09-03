package com.coderslagoon.crypto.estreamj.ciphers.spritz;

import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.ICipher;
import com.coderslagoon.crypto.estreamj.framework.Utils;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SpritzTest {

    @Test
    public void testCipher() throws ESJException {
        assertTrue(Spritz.isCompatible());
        Spritz s = new Spritz();
        assertEquals(1, s.getWordSize());
        final byte[] key = new byte[1 + s.getKeySize()];
        for (int i = 1; i < key.length; i++)
            key[i] = (byte)(80 + i);
        final byte[] iv = new byte[1 + s.getNonceSize()];
        for (int i = 1; i < iv.length; i++)
            iv[i] = (byte)i;
        byte[] plainText = new byte[257];
        for (int i = 1; i < plainText.length; i++)
            plainText[i] = (byte)i;
        s.setupKey(ICipher.MODE_ENCRYPT, key, 1);
        s.setupNonce(iv, 1);
        byte[] cipherText = new byte[1 + plainText.length + 1];
        s.process(plainText, 1, cipherText, 1, 256);
        assertEquals(0, cipherText[0]);
        assertEquals(0, cipherText[257]);
        for (int i = 1; i < plainText.length; i++)
            assertEquals(plainText[i], (byte)i);
        key[0] = iv[0] = (byte)0xcc;
        s = new Spritz();
        s.setupKey(ICipher.MODE_DECRYPT, key, 1);
        s.setupNonce(iv, 1);
        byte[] plainText2 = new byte[256];
        s.process(cipherText, 1, plainText2, 0, 256);
        assertTrue(Utils.arraysEquals(plainText, 1, plainText2, 0, 256));
        s.erase();
    }
}
