package com.coderslagoon.crypto.estreamj.framework;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.util.Arrays;

public class Utils {
    private Utils() {}

    public static void fillPattern123(byte[] buf, int ofs, int len) {
        int counter, end;

        counter = 0;
        end = ofs + len;
        while (ofs < end) {
            buf[ofs++] = (byte)counter++;
        }
    }

    public static boolean checkPattern123(byte[] buf, int ofs, int len) {
        int counter, end;

        counter = 0;
        end = ofs + len;
        while (ofs < end) {
            if (buf[ofs] != (byte)counter) {
                return false;
            }
            counter++;
            ofs++;
        }
        return true;
    }

    public static byte[] makeOutputBuffer(int len, int extraLen) {
        byte[] result = new byte[len + extraLen];
        Arrays.fill(result, (byte)0xcc);
        return result;
    }

    public static boolean arraysEquals(
            byte[] a, int ofsA, byte[] b, int ofsB, int len) {
        int end = ofsA + len;
        while (ofsA < end) {
            if (b[ofsB++] != a[ofsA++]) {
                return false;
            }
        }
        return true;
    }

    public static final int readInt32LE(byte[] data, int ofs) {
        return ( data[ofs + 3]         << 24) |
               ((data[ofs + 2] & 0xff) << 16) |
               ((data[ofs + 1] & 0xff) <<  8) |
                (data[ofs    ] & 0xff);
    }

    public static final void writeInt32LE(int value, byte[] data, int ofs) {
        data[ofs    ] = (byte)(value       );
        data[ofs + 1] = (byte)(value >>>  8);
        data[ofs + 2] = (byte)(value >>> 16);
        data[ofs + 3] = (byte)(value >>> 24);
    }

    public static final int readInt32BE(byte[] data, int ofs) {
        return ( data[ofs    ]         << 24) |
               ((data[ofs + 1] & 0xff) << 16) |
               ((data[ofs + 2] & 0xff) <<  8) |
                (data[ofs + 3] & 0xff);
    }

    public static final void writeInt32BE(int value, byte[] data, int ofs) {
        data[ofs + 3] = (byte)(value       );
        data[ofs + 2] = (byte)(value >>>  8);
        data[ofs + 1] = (byte)(value >>> 16);
        data[ofs    ] = (byte)(value >>> 24);
    }

    public static final long readInt64BE(byte[] data, int ofs) {
        return ((long) data[ofs    ]         << 56) |
               ((long)(data[ofs + 1] & 0xff) << 48) |
               ((long)(data[ofs + 2] & 0xff) << 40) |
               ((long)(data[ofs + 3] & 0xff) << 32) |
               ((long)(data[ofs + 4] & 0xff) << 24) |
                     ((data[ofs + 5] & 0xff) << 16) |
                     ((data[ofs + 6] & 0xff) <<  8) |
                      (data[ofs + 7] & 0xff);
    }

    public static final void writeInt64BE(long value, byte[] data, int ofs) {
        data[ofs + 7] = (byte) value       ;
        data[ofs + 6] = (byte)(value >>>  8);
        data[ofs + 5] = (byte)(value >>> 16);
        data[ofs + 4] = (byte)(value >>> 24);
        data[ofs + 3] = (byte)(value >>> 32);
        data[ofs + 2] = (byte)(value >>> 40);
        data[ofs + 1] = (byte)(value >>> 48);
        data[ofs    ] = (byte)(value >>> 56);
    }

    public static byte[] hexStrToBytes(String hex) {
        int len = hex.length();
        if (1 == (len & 1)) {
            return null;
        }
        byte[] result = new byte[len >> 1];
        int r = 0;
        int pos = 0;
        while (pos < len) {
            int reg = 0;
            for (int nI = 0; nI < 2; nI++) {
                reg <<= 4;
                char c = Character.toLowerCase(hex.charAt(pos++));
                if ('0' <= c && '9' >= c) {
                    reg |= c - '0';
                }
                else if ('a' <= c && 'f' >= c) {
                    reg |= (c - 'a') + 10;
                }
                else {
                    return null;
                }
            }
            result[r++] = (byte)reg;
        }
        return result;
    }

    static final char[] HEXTAB = {
        '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'
    };

    public static int hexDump(
        InputStream is,
        PrintStream ps,
        int maxRead,
        int bytesPerLine) {
        int read, chr, i, result;
        char[] pad;
        StringBuilder left, right;

        if (1 > bytesPerLine) {
            bytesPerLine = 1;
        }

        left = new StringBuilder();
        right = new StringBuilder();

        result = 0;

        for (read = 0, i = 0;;) {
            if (-1 != maxRead && maxRead <= read) {
                break;
            }

            try {
                if (-1 == (chr = is.read())) {
                    break;
                }
            }
            catch (IOException ioe) {
                break;
            }

            result++;

            if (0 < i++) {
                left.append(' ');
            }

            left.append(HEXTAB[chr >>> 4]);
            left.append(HEXTAB[chr & 0x0f]);

            right.append((chr < ' ') ? '.' : (char)chr);

            if (0 == (i % bytesPerLine)) {
                ps.print(left.toString());
                ps.print("    ");
                ps.println(right.toString());

                left.setLength(0);
                right.setLength(0);

                i = 0;
            }
        }

        if (0 < i) {
            pad = new char[((bytesPerLine - i) * 3) + 4];
            Arrays.fill(pad, ' ');

            ps.print(left.toString());
            ps.print(pad);
            ps.println(right.toString());
        }

        return result;
    }

    public static byte[] swapByteOrder32(byte[] data, int ofs, int len) {
        int end = ofs + len;
        byte tmp;

        for (; ofs < end; ofs += 4) {
            tmp = data[ofs];
            data[ofs] = data[ofs + 3];
            data[ofs + 3] = tmp;

            tmp = data[ofs + 1];
            data[ofs + 1] = data[ofs + 2];
            data[ofs + 2] = tmp;
        }
        return data;
    }
}
