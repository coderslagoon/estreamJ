package com.coderslagoon.crypto.estreamj.ciphers.grain;

import com.coderslagoon.crypto.estreamj.framework.ESJException;
import com.coderslagoon.crypto.estreamj.framework.Engine;
import com.coderslagoon.crypto.estreamj.framework.ICipher;
import com.coderslagoon.crypto.estreamj.framework.ICipherMaker;

public class Grain128Noopt extends GrainRefNoopt {
    public Grain128Noopt() {
        super();
    }

    public int getKeySize() {
        return 16;
    }

    public int getNonceSize() {
        return 12;
    }

    protected int keyStream() {
        int[] N = this.NFSR;
        int[] L = this.LFSR;

        int result = N[2]^N[15]^N[36]^N[45]^N[64]^N[73]^N[89]^L[93]^(N[12]&L[8])^(L[13]&L[20])^(N[95]&L[42])^(L[60]&L[79])^(N[12]&N[95]&L[95]);

        int nbit = L[0]^N[0]^N[26]^N[56]^N[91]^N[96]^(N[3]&N[67])^(N[11]&N[13])^(N[17]&N[18])^(N[27]&N[59])^(N[40]&N[48])^(N[61]&N[65])^(N[68]&N[84]);
        int lbit = L[0]^L[7]^L[38]^L[70]^L[81]^L[96];

        for (int i = 1; i < 128; ++i) {
            N[i - 1] = N[i];
            L[i - 1] = L[i];
        }

        N[127] = nbit;
        L[127] = lbit;

        return result;
    }

    ///////////////////////////////////////////////////////////////////////////

    static class Maker implements ICipherMaker {
        public ICipher create() throws ESJException {
            return new Grain128Noopt();
        }

        public String getName() {
            return "Grain-128-noopt";
        }
    }

    public static void register() {
        Engine.registerCipher(new Maker());
    }
}
