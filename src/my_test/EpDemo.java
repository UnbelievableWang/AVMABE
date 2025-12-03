package my_test;

import it.unisa.dia.gas.jpbc.Element;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class EpDemo {

    private static String ms(long nanos) {
        return String.format("%.3f ms", nanos / 1_000_000.0);
    }
    private static void printRow(String label, long nanos) {
        System.out.println(String.format("%-7s : %s", label, ms(nanos)));
    }

    private static void warmup(EpPP pp) {
        Element g1 = pp.g1, g2 = pp.g2;
        for (int i = 0; i < 8; i++) {
            BigInteger e = pp.randZqBI();
            pp.g1PP.powZn(pp.Zq.newElement(e));
            pp.g2PP.powZn(pp.Zq.newElement(e));
        }
        pp.pairing.pairing(g1, g2);
    }

    private static BigInteger[][] buildGammaNofN(int attrSize, BigInteger q) {
        BigInteger[][] Gamma = new BigInteger[attrSize][attrSize];
        for (int x = 0; x < attrSize; x++) {
            BigInteger alpha = BigInteger.valueOf(x + 1L);
            BigInteger pow = BigInteger.ONE;
            for (int j = 0; j < attrSize; j++) {
                Gamma[x][j] = pow.mod(q);
                pow = pow.multiply(alpha).mod(q);
            }
        }
        return Gamma;
    }

    public static void main(String[] args) {

        int[] attrSizes = new int[]{100, 500, 1000};

        for (int ATTR_SIZE : attrSizes) {
            System.out.println();
            System.out.println("========== ATTR_SIZE = " + ATTR_SIZE + " ==========");

            long T0 = System.nanoTime();

            long t_gs_s = System.nanoTime();
            EpPP pp = new EpPP(256, 1536);
            warmup(pp);
            long t_gs_e = System.nanoTime();

            long t_as_s = System.nanoTime();
            Map<Integer, EpAuthority> AAs = new HashMap<>();
            for (int a = 0; a < ATTR_SIZE; a++) {
                AAs.put(a, new EpAuthority(pp, a));
            }
            long t_as_e = System.nanoTime();

            BigInteger[][] Gamma = buildGammaNofN(ATTR_SIZE, pp.q);

            Map<Integer,Integer> rho = new HashMap<>();
            for (int x = 0; x < ATTR_SIZE; x++) {
                rho.put(x, x);
            }
            EpPolicy policy = new EpPolicy(Gamma, rho);


            long t_kg_s = System.nanoTime();
            EpUser u = new EpUser("RID-ALICE");
            for (int a = 0; a < ATTR_SIZE; a++) {
                u.receiveFromAuthority(pp, a, AAs.get(a));
            }
            long t_kg_e = System.nanoTime();


            long t_tk_s = System.nanoTime();
            java.util.List<Integer> tkAttrs = new ArrayList<>();
            for (int a = 0; a < ATTR_SIZE; a++) tkAttrs.add(a);
            u.tkGen(pp, tkAttrs);
            long t_tk_e = System.nanoTime();


            long t_enc_s = System.nanoTime();
            byte[] mu = "hello-ehealth".getBytes(StandardCharsets.UTF_8);
            EpCiphertext ct = EpEncTransDec.enc(pp, AAs, policy, mu);
            long t_enc_e = System.nanoTime();


            long t_tr_s = System.nanoTime();
            EpPDCT pd = EpEncTransDec.trans(pp, u, AAs, ct);
            long t_tr_e = System.nanoTime();


            long t_dec_s = System.nanoTime();
            byte[] dec = EpEncTransDec.dec(pp, u, pd);
            long t_dec_e = System.nanoTime();

            long T1 = System.nanoTime();

            System.out.println(String.format("µ(dec)%4s= %s", "", new String(dec, StandardCharsets.UTF_8)));
            System.out.println("---- per-stage ----");
            printRow("GSetup", t_gs_e - t_gs_s);
            printRow("ASetup", t_as_e - t_as_s);
            printRow("KGen",   t_kg_e - t_kg_s);
            printRow("TKGen",  t_tk_e - t_tk_s);
            printRow("Enc",    t_enc_e - t_enc_s);
            printRow("Trans",  t_tr_e - t_tr_s);
            printRow("Dec",    t_dec_e - t_dec_s);
            System.out.println("-------------------");
            printRow("Total",  T1 - T0);
        }
    }
}
