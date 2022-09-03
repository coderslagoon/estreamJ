package com.coderslagoon.crypto.estreamj.ciphers.aes;

/**
 * memory efficient AES implementation; based on the work of Brian Gladman's
 * optimizations and C code and the Bouncy Castle translation to Java; the
 * class files' size went down to 2/3 of the original size (even after splitting
 * of the shared base class); it is still faster since some unnecessary [&gt;&gt; &amp;]
 * operations have been taken out and got replaced with [&gt;&gt;&gt;]
 */
public class AESLean extends AES {
    protected void encryptBlock(int[][] KW) {
        int r, r0, r1, r2, r3;

        this.C0 ^= KW[0][0];
        this.C1 ^= KW[0][1];
        this.C2 ^= KW[0][2];
        this.C3 ^= KW[0][3];

        for (r = 1; r < this.ROUNDS - 1;) {
            r0 = mcol((S[this.C0&255]&255) ^ ((S[(this.C1>>8)&255]&255)<<8) ^ ((S[(this.C2>>16)&255]&255)<<16) ^ (S[this.C3>>>24]<<24)) ^ KW[r][0];
            r1 = mcol((S[this.C1&255]&255) ^ ((S[(this.C2>>8)&255]&255)<<8) ^ ((S[(this.C3>>16)&255]&255)<<16) ^ (S[this.C0>>>24]<<24)) ^ KW[r][1];
            r2 = mcol((S[this.C2&255]&255) ^ ((S[(this.C3>>8)&255]&255)<<8) ^ ((S[(this.C0>>16)&255]&255)<<16) ^ (S[this.C1>>>24]<<24)) ^ KW[r][2];
            r3 = mcol((S[this.C3&255]&255) ^ ((S[(this.C0>>8)&255]&255)<<8) ^ ((S[(this.C1>>16)&255]&255)<<16) ^ (S[this.C2>>>24]<<24)) ^ KW[r++][3];
            this.C0 = mcol((S[r0&255]&255) ^ ((S[(r1>>8)&255]&255)<<8) ^ ((S[(r2>>16)&255]&255)<<16) ^ (S[r3>>>24]<<24)) ^ KW[r][0];
            this.C1 = mcol((S[r1&255]&255) ^ ((S[(r2>>8)&255]&255)<<8) ^ ((S[(r3>>16)&255]&255)<<16) ^ (S[r0>>>24]<<24)) ^ KW[r][1];
            this.C2 = mcol((S[r2&255]&255) ^ ((S[(r3>>8)&255]&255)<<8) ^ ((S[(r0>>16)&255]&255)<<16) ^ (S[r1>>>24]<<24)) ^ KW[r][2];
            this.C3 = mcol((S[r3&255]&255) ^ ((S[(r0>>8)&255]&255)<<8) ^ ((S[(r1>>16)&255]&255)<<16) ^ (S[r2>>>24]<<24)) ^ KW[r++][3];
        }

        r0 = mcol((S[this.C0&255]&255) ^ ((S[(this.C1>>8)&255]&255)<<8) ^ ((S[(this.C2>>16)&255]&255)<<16) ^ (S[(this.C3>>>24)]<<24)) ^ KW[r][0];
        r1 = mcol((S[this.C1&255]&255) ^ ((S[(this.C2>>8)&255]&255)<<8) ^ ((S[(this.C3>>16)&255]&255)<<16) ^ (S[(this.C0>>>24)]<<24)) ^ KW[r][1];
        r2 = mcol((S[this.C2&255]&255) ^ ((S[(this.C3>>8)&255]&255)<<8) ^ ((S[(this.C0>>16)&255]&255)<<16) ^ (S[(this.C1>>>24)]<<24)) ^ KW[r][2];
        r3 = mcol((S[this.C3&255]&255) ^ ((S[(this.C0>>8)&255]&255)<<8) ^ ((S[(this.C1>>16)&255]&255)<<16) ^ (S[(this.C2>>>24)]<<24)) ^ KW[r++][3];

        this.C0 = (S[r0&255]&255) ^ ((S[(r1>>8)&255]&255)<<8) ^ ((S[(r2>>16)&255]&255)<<16) ^ (S[r3>>>24]<<24) ^ KW[r][0];
        this.C1 = (S[r1&255]&255) ^ ((S[(r2>>8)&255]&255)<<8) ^ ((S[(r3>>16)&255]&255)<<16) ^ (S[r0>>>24]<<24) ^ KW[r][1];
        this.C2 = (S[r2&255]&255) ^ ((S[(r3>>8)&255]&255)<<8) ^ ((S[(r0>>16)&255]&255)<<16) ^ (S[r1>>>24]<<24) ^ KW[r][2];
        this.C3 = (S[r3&255]&255) ^ ((S[(r0>>8)&255]&255)<<8) ^ ((S[(r1>>16)&255]&255)<<16) ^ (S[r2>>>24]<<24) ^ KW[r][3];
    }

    protected final void decryptBlock(int[][] KW) {
        int r, r0, r1, r2, r3;

        this.C0 ^= KW[this.ROUNDS][0];
        this.C1 ^= KW[this.ROUNDS][1];
        this.C2 ^= KW[this.ROUNDS][2];
        this.C3 ^= KW[this.ROUNDS][3];

        for (r = this.ROUNDS - 1; r > 1;) {
            r0 = inv_mcol((Si[this.C0&255]&255) ^ ((Si[(this.C3>>8)&255]&255)<<8) ^ ((Si[(this.C2>>16)&255]&255)<<16) ^ (Si[this.C1>>>24]<<24)) ^ KW[r][0];
            r1 = inv_mcol((Si[this.C1&255]&255) ^ ((Si[(this.C0>>8)&255]&255)<<8) ^ ((Si[(this.C3>>16)&255]&255)<<16) ^ (Si[this.C2>>>24]<<24)) ^ KW[r][1];
            r2 = inv_mcol((Si[this.C2&255]&255) ^ ((Si[(this.C1>>8)&255]&255)<<8) ^ ((Si[(this.C0>>16)&255]&255)<<16) ^ (Si[this.C3>>>24]<<24)) ^ KW[r][2];
            r3 = inv_mcol((Si[this.C3&255]&255) ^ ((Si[(this.C2>>8)&255]&255)<<8) ^ ((Si[(this.C1>>16)&255]&255)<<16) ^ (Si[this.C0>>>24]<<24)) ^ KW[r--][3];
            this.C0 = inv_mcol((Si[r0&255]&255) ^ ((Si[(r3>>8)&255]&255)<<8) ^ ((Si[(r2>>16)&255]&255)<<16) ^ (Si[r1>>>24]<<24)) ^ KW[r][0];
            this.C1 = inv_mcol((Si[r1&255]&255) ^ ((Si[(r0>>8)&255]&255)<<8) ^ ((Si[(r3>>16)&255]&255)<<16) ^ (Si[r2>>>24]<<24)) ^ KW[r][1];
            this.C2 = inv_mcol((Si[r2&255]&255) ^ ((Si[(r1>>8)&255]&255)<<8) ^ ((Si[(r0>>16)&255]&255)<<16) ^ (Si[r3>>>24]<<24)) ^ KW[r][2];
            this.C3 = inv_mcol((Si[r3&255]&255) ^ ((Si[(r2>>8)&255]&255)<<8) ^ ((Si[(r1>>16)&255]&255)<<16) ^ (Si[r0>>>24]<<24)) ^ KW[r--][3];
        }

        r0 = inv_mcol((Si[this.C0&255]&255) ^ ((Si[(this.C3>>8)&255]&255)<<8) ^ ((Si[(this.C2>>16)&255]&255)<<16) ^ (Si[this.C1>>>24]<<24)) ^ KW[r][0];
        r1 = inv_mcol((Si[this.C1&255]&255) ^ ((Si[(this.C0>>8)&255]&255)<<8) ^ ((Si[(this.C3>>16)&255]&255)<<16) ^ (Si[this.C2>>>24]<<24)) ^ KW[r][1];
        r2 = inv_mcol((Si[this.C2&255]&255) ^ ((Si[(this.C1>>8)&255]&255)<<8) ^ ((Si[(this.C0>>16)&255]&255)<<16) ^ (Si[this.C3>>>24]<<24)) ^ KW[r][2];
        r3 = inv_mcol((Si[this.C3&255]&255) ^ ((Si[(this.C2>>8)&255]&255)<<8) ^ ((Si[(this.C1>>16)&255]&255)<<16) ^ (Si[this.C0>>>24]<<24)) ^ KW[r][3];

        this.C0 = (Si[r0&255]&255) ^ ((Si[(r3>>8)&255]&255)<<8) ^ ((Si[(r2>>16)&255]&255)<<16) ^ (Si[r1>>>24]<<24) ^ KW[0][0];
        this.C1 = (Si[r1&255]&255) ^ ((Si[(r0>>8)&255]&255)<<8) ^ ((Si[(r3>>16)&255]&255)<<16) ^ (Si[r2>>>24]<<24) ^ KW[0][1];
        this.C2 = (Si[r2&255]&255) ^ ((Si[(r1>>8)&255]&255)<<8) ^ ((Si[(r0>>16)&255]&255)<<16) ^ (Si[r3>>>24]<<24) ^ KW[0][2];
        this.C3 = (Si[r3&255]&255) ^ ((Si[(r2>>8)&255]&255)<<8) ^ ((Si[(r1>>16)&255]&255)<<16) ^ (Si[r0>>>24]<<24) ^ KW[0][3];
    }
}
