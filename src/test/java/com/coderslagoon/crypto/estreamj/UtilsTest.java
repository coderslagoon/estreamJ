package com.coderslagoon.crypto.estreamj;

import java.util.Arrays;

import com.coderslagoon.crypto.estreamj.framework.Utils;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class UtilsTest {
    @Test
    public void testHexStrToBytes() {
        byte[] b;

        assertEquals(null, Utils.hexStrToBytes("x"));
        assertEquals(null, Utils.hexStrToBytes("aaX"));
        assertEquals(null, Utils.hexStrToBytes("00a"));
        assertEquals(null, Utils.hexStrToBytes("123"));
        assertEquals(null, Utils.hexStrToBytes("(*%^()^%(&^@&%^@&#43"));

        b = Utils.hexStrToBytes("");
        assertEquals(0, b.length);
        b = Utils.hexStrToBytes("00");
        assertEquals(1, b.length);
        assertEquals(0, b[0]);
        b = Utils.hexStrToBytes("ff");
        assertEquals(1, b.length);
        assertEquals((byte)0xff, b[0]);
        b = Utils.hexStrToBytes("0123456789abcdef");
        assertEquals(8, b.length);
        assertEquals((byte)0x01, b[0]); assertEquals((byte)0x23, b[1]);
        assertEquals((byte)0x45, b[2]); assertEquals((byte)0x67, b[3]);
        assertEquals((byte)0x89, b[4]); assertEquals((byte)0xab, b[5]);
        assertEquals((byte)0xcd, b[6]); assertEquals((byte)0xef, b[7]);
        b = Utils.hexStrToBytes("BAADF00D");
        assertEquals(4, b.length);
        assertEquals((byte)0xba, b[0]); assertEquals((byte)0xad, b[1]);
        assertEquals((byte)0xf0, b[2]); assertEquals((byte)0x0d, b[3]);
    }

    ///////////////////////////////////////////////////////////////////////////

    @Test
    public void testByteConvertors() {
        assertEquals(0, Utils.readInt32LE(new byte[] {0,0,0,0}, 0));
        assertEquals(1, Utils.readInt32LE(new byte[] {1,0,0,0}, 0));
        assertEquals(1, Utils.readInt32LE(new byte[] {0, 1,0,0,0}, 1));
        assertEquals(0x01234567,
            Utils.readInt32LE(new byte[] {(byte)0xcc, 0x67, 0x45, 0x23, 1}, 1));

        byte[] testArray64 = new byte[] { (byte)0xcc,
                    1,        0x23,       0x45,       0x67,
            (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef, (byte)0xee };

        long int64 = Utils.readInt64BE(testArray64, 1);
        assertEquals(0x0123456789abcdefL, int64);
        byte[] arrOut = new byte[10];
        arrOut[0] = (byte)0xcc;
        arrOut[9] = (byte)0xee;
        Utils.writeInt64BE(0x0123456789abcdefL, arrOut, 1);
        Arrays.equals(testArray64, arrOut);

        byte[] buf = new byte[6];
        Arrays.fill(buf, (byte)0xcc);
        Utils.writeInt32LE(0, buf, 1);
        assertEquals((byte)0xcc, buf[0]);
        assertEquals((byte)0xcc, buf[5]);
        assertEquals(0, buf[1]);
        assertEquals(0, buf[2]);
        assertEquals(0, buf[3]);
        assertEquals(0, buf[4]);
        Arrays.fill(buf, (byte)0xcc);
        Utils.writeInt32LE(0xcaffbabe, buf, 2);
        assertEquals(0xbe, (buf[2] & 0x0ff));
        assertEquals(0xba, (buf[3] & 0x0ff));
        assertEquals(0xff, (buf[4] & 0x0ff));
        assertEquals(0xca, (buf[5] & 0x0ff));
    }

    ///////////////////////////////////////////////////////////////////////////

    @Test
    public void testSwapByteOrder32() {
        byte[] data;

        data = new byte[0];
        assertEquals(data, Utils.swapByteOrder32(data, 0, data.length));

        data = new byte[4];
        data[0] = 1;
        data[1] = 2;
        data[2] = 3;
        data[3] = 4;
        assertEquals(data, Utils.swapByteOrder32(data, 0, data.length));
        assertEquals(4, data[0]);
        assertEquals(3, data[1]);
        assertEquals(2, data[2]);
        assertEquals(1, data[3]);

        data = new byte[10];
        data[0] = (byte)0x42;
        data[1] = 4;
        data[2] = 3;
        data[3] = 2;
        data[4] = 1;
        data[5] = (byte)0xaa;
        data[6] = (byte)0xbb;
        data[7] = (byte)0xcc;
        data[8] = (byte)0xdd;
        data[9] = 117;
        assertEquals(data, Utils.swapByteOrder32(data, 1, 8));
        assertEquals((byte)0x42, data[0]);
        assertEquals(1, data[1]);
        assertEquals(2, data[2]);
        assertEquals(3, data[3]);
        assertEquals(4, data[4]);
        assertEquals((byte)0xdd, data[5]);
        assertEquals((byte)0xcc, data[6]);
        assertEquals((byte)0xbb, data[7]);
        assertEquals((byte)0xaa, data[8]);
        assertEquals(117, data[9]);

        try {
            data = new byte[5];
            Utils.swapByteOrder32(data, 0, data.length);
            fail();
        }
        catch (ArrayIndexOutOfBoundsException aioobe) {
        }
    }
}
