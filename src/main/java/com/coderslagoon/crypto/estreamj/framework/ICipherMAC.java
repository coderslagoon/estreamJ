package com.coderslagoon.crypto.estreamj.framework;

/**
 * Stream ciphers which also do MAC computation implement this interface.
 */
public interface  ICipherMAC extends ICipher {
    /**
     * @return MAC size in bytes
     */
    public int getMacSize();

    /**
     * Processes AAD (additional authentication data).
     * @param buf input buffer
     * @param ofs where to start reading from the input buffer
     * @param len number of bytes to process, must be aligned to the cipher's
     * word size except on the last call where an arbitrary size can be used
     * @throws ESJException in any error occurred
     */
    public void processAAD(byte[] buf, int ofs, int len) throws ESJException;

    /**
     * Finalize and compute the MAC.
     * @param macBuf MAC buffer
     * @param macOfs where to write MAC
     * @throws ESJException if any error occurred
     */
    public void finalize(byte[] macBuf, int macOfs) throws ESJException;
}
