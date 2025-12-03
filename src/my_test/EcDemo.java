package my_test;

import it.unisa.dia.gas.jpbc.Element;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class EcDemo {

    private static double ms(long t0, long t1) { return (t1 - t0) / 1e6; }
    private static void printMs(String k, double v) { System.out.printf("%-10s: %.3f ms%n", k, v); }

    private static EcMatrix buildGammaNofN(int n, BigInteger modN) {
        EcMatrix G = new EcMatrix(n, n);
        for (int row = 0; row < n; row++) {
            BigInteger alpha = BigInteger.valueOf(row + 1L);
            BigInteger pow = BigInteger.ONE;
            for (int col = 0; col < n; col++) {
                G.set(row, col, pow.mod(modN));
                pow = pow.multiply(alpha).mod(modN);
            }
        }
        return G;
    }

    private static EcMatrix buildReconCNofN(int n, BigInteger modN) {
        EcMatrix C = new EcMatrix(1, n);
        for (int i = 0; i < n; i++) {
            BigInteger alpha_i = BigInteger.valueOf(i + 1L);
            BigInteger num = BigInteger.ONE;
            BigInteger den = BigInteger.ONE;
            for (int k = 0; k < n; k++) {
                if (k == i) continue;
                BigInteger alpha_k = BigInteger.valueOf(k + 1L);

                // numerator *= -α_k
                num = num.multiply(alpha_k.negate()).mod(modN);

                // denominator *= (α_i - α_k)
                BigInteger diff = alpha_i.subtract(alpha_k).mod(modN);
                den = den.multiply(diff).mod(modN);
            }
            BigInteger denInv = den.modInverse(modN);
            BigInteger li0 = num.multiply(denInv).mod(modN);
            if (li0.signum() < 0) li0 = li0.add(modN);

            C.set(0, i, li0);
        }
        return C;
    }

    public static void main(String[] args) {

        int numPrimes = 3, qBit = 512;
        String RID = "RID-ALICE";
        byte[] mu = "hello-ehealth".getBytes(StandardCharsets.UTF_8);

        int[] attrSizes = {100, 500, 1000};

        for (int ATTR_SIZE : attrSizes) {

            System.out.println("\n========== ATTR_SIZE = " + ATTR_SIZE + " ==========");


            int[] attrs = new int[ATTR_SIZE];
            for (int i = 0; i < ATTR_SIZE; i++) attrs[i] = i;

            long T0 = System.nanoTime(), t0, t1;


            t0 = System.nanoTime();
            EcPP pp = new EcPP(numPrimes, qBit);
            t1 = System.nanoTime();
            double tG = ms(t0,t1);

            t0 = System.nanoTime();
            Map<Integer, EcAuthority> AAs = new HashMap<>();
            for (int a : attrs) AAs.put(a, new EcAuthority(pp, a));
            t1 = System.nanoTime();
            double tA = ms(t0,t1);


            t0 = System.nanoTime();
            EcUser u = new EcUser(RID);
            for (int a : attrs) u.receiveKey(a, AAs.get(a).keyGen(pp, RID));
            t1 = System.nanoTime();
            double tKG = ms(t0,t1);

            EcMatrix Gamma = buildGammaNofN(ATTR_SIZE, pp.N);

            HashMap<Integer, Integer> rho = new HashMap<>();
            for (int row = 0; row < ATTR_SIZE; row++)
                rho.put(row, attrs[row]); 

            EcPolicy Arho = new EcPolicy(Gamma, rho);


            t0 = System.nanoTime();
            List<Integer> tkAttrs = new ArrayList<>();
            for (int a : attrs) tkAttrs.add(a);
            Map<Integer, EcUser.TukPair> tuks = u.tkGen(pp, tkAttrs);
            t1 = System.nanoTime();
            double tTK = ms(t0,t1);


            t0 = System.nanoTime();
            EcCiphertext ct = EcEncTransDec.enc(pp, AAs, Arho, Gamma, mu);
            t1 = System.nanoTime();
            double tE = ms(t0,t1);

            EcMatrix c = buildReconCNofN(ATTR_SIZE, pp.N);
            t0 = System.nanoTime();
            EcPDCT pd = EcEncTransDec.trans(pp, RID, tuks, ct, c);
            t1 = System.nanoTime();
            double tT = ms(t0,t1);


            Map<Integer, Element> T2_byAttr = new HashMap<>();
            for (var e : pd.T2_byRow.entrySet()) {
                int row = e.getKey();
                int attr = Arho.rho(row);
                Element prev = T2_byAttr.get(attr);
                T2_byAttr.put(attr,
                        prev == null ? e.getValue() : prev.mul(e.getValue()).getImmutable());
            }

            // Dec
            t0 = System.nanoTime();
            byte[] muDec = EcEncTransDec.dec2(pp, pd.C0, pd.T1, T2_byAttr, u.zMap);
            t1 = System.nanoTime();
            double tD = ms(t0,t1);

            long T1 = System.nanoTime();
            double T = ms(T0,T1);

            System.out.println("µ(dec)   = " + new String(muDec, StandardCharsets.UTF_8));
            System.out.println("---- per-stage ----");
            printMs("GSetup", tG);
            printMs("ASetup", tA);
            printMs("KGen",   tKG);
            printMs("TKGen",  tTK);
            printMs("Enc",    tE);
            printMs("Trans",  tT);
            printMs("Dec",    tD);
            System.out.println("-------------------");
            printMs("Total",  T);
        }
    }
}

