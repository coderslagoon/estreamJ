package com.coderslagoon.crypto.estreamj.labs;

import java.io.PrintStream;
import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.Engine;
import com.coderslagoon.crypto.estreamj.framework.ICipher;

public class PerformanceLab {

    static class Tester implements Runnable {
        public static final int DEF_BUF_SIZE = 4 * 1024;
        public static final int DEF_TEST_RUN_SECS = 5;

        boolean aborted;
        PrintStream out;
        int bufSize;
        int testRunSecs;

        public Tester(
                PrintStream out,
                int bufSize,
                int testRunSecs) {
            this.aborted = false;
            this.out = out;
            this.bufSize = -1 == bufSize ? DEF_BUF_SIZE : bufSize;
            this.testRunSecs = -1 == testRunSecs ? DEF_TEST_RUN_SECS :
                                     testRunSecs;
        }

        public void abort() {
            this.aborted = true;
        }

        public void run() {
            try {
                String[] ciphers = Engine.getCipherNames();

                for (String cipher : ciphers) {
                    if (this.aborted) {
                        break;
                    }
                    if (perform(cipher)) {
                        break;
                    }
                }

                if (this.aborted) {
                    this.out.println("\nABORTED!");
                }
                else {
                    this.out.println("Done.");
                }
            }
            catch (Exception e) {
                this.out.println("\nUNEXPECTED ERROR (" + e.getMessage() + ")");
                e.printStackTrace(this.out);
            }
            this.out.flush();
        }

        ///////////////////////////////////////////////////////////////////////

        // TODO: add keysetup performance test
        // TODO: add extra testing for ciphers which support MAC computation

        protected boolean perform(String cipherName) {
            long start, end, trueEnd, tm, rate, total;
            int bufSize;
            ICipher cph;
            byte[] bufIn, bufOut;

            this.out.print("testing [" + cipherName + "] ...");
            this.out.flush();

            try {
                // TODO: make this quite primitive approach more flexible, e.g.
                //        we could test the system speed first, "heat up" the
                //        JIT/Hotspot compiler to have the code optimized and
                //        the core parts nicely cached, test multiple buffer
                //        sizes and so on - the sky is the limit

                cph = Engine.createCipher(cipherName);
                cph.setupKey(
                        ICipher.MODE_ENCRYPT,
                        new byte[cph.getKeySize()],
                        0);
                cph.setupNonce(
                        new byte[cph.getNonceSize()],
                        0);

                // align the buffer size to the next word size
                bufSize = this.bufSize - (this.bufSize % cph.getWordSize());
                if (0 == bufSize) {
                    bufSize = cph.getWordSize();
                }
                bufIn = new byte[bufSize];
                bufOut = bufIn.clone();

                start = System.currentTimeMillis();
                end =  start + this.testRunSecs * 1000;

                // FIXME: the overhead of the time gathering doesn't make the
                //         tests 100% fair, since it'll get executed more often
                //         with fast ciphers (maybe an adaptive solution could
                //         help?)
                total = 0;
                while (end > (trueEnd = System.currentTimeMillis())) {
                    cph.process(bufIn, 0, bufOut, 0, bufSize);

                    total += bufSize;

                    if (this.aborted) {
                        return true;
                    }
                }
                tm = trueEnd - start;
                if (0 == tm) {
                    tm = 1;
                }

                rate = (total * 1000000L) / tm;
                rate /= 1000;
                rate /= 1024;

                this.out.printf(" OK -- %,d kB per second%n", rate);
                cph.erase();
            }
            catch (ESJException esje) {
                this.out.println(" ERROR (" + esje.getMessage() + ")");
            }
            this.out.flush();

            return false;
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Command line application entry point.
     * @param args parameters
     */
    public static void main(String[] args) {
        Tester tester = new Tester(System.out, -1, -1);
        tester.run();
    }
}
