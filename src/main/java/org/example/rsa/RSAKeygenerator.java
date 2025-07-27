package org.example.rsa;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.List;

public class RSAKeygenerator {
    private static final SecureRandom random = new SecureRandom();
    private static final int[] OFFSETS = {1, 7, 11, 13, 17, 19, 23, 29};

    public static void main(String[] args) {
        if (args.length != 4) {
            System.err.println("Usage: java rsa.RSAKeygenerator <bitLength> <privOut> <pubOut> <primesOut>");
            System.exit(1);
        }
        int bitLength       = Integer.parseInt(args[0]);
        Path privPath       = Paths.get(args[1]);
        Path pubPath        = Paths.get(args[2]);
        Path primesPath     = Paths.get(args[3]);

        try {
            generate(bitLength, privPath, pubPath, primesPath);
            System.out.println("Keys generated successfully.");
        } catch (IOException ex) {
            System.err.println("I/O error: " + ex.getMessage());
            System.exit(2);
        }
    }

    /**
     * Generiert RSA-Schlüssel:
     * - zwei Primzahlen p,q
     * - n=p*q, phi=(p-1)(q-1)
     * - öffentlichen Exponenten e (ggT(e,phi)=1)
     * - privaten Exponenten d = e^(-1) mod phi
     * und schreibt private, public Keys sowie die Primzahlen.
     */
    public static void generate(int bitLength,
                                Path privOut,
                                Path pubOut,
                                Path primesOut) throws IOException {
        System.out.println("Generating prime p...");
        BigInteger p = generatePrime(bitLength);
        System.out.println("Generating prime q...");
        BigInteger q = generatePrime(bitLength);

        BigInteger n   = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE)
                .multiply(q.subtract(BigInteger.ONE));

        BigInteger e;
        do {
            // Zufall im Intervall [2, phi-1]
            e = new BigInteger(phi.bitLength(), random)
                    .mod(phi.subtract(BigInteger.TWO))  // jetzt [0, phi-3]
                    .add(BigInteger.TWO);               // jetzt [2, phi-1]
        } while (!phi.gcd(e).equals(BigInteger.ONE));

        BigInteger d = modInverse(e, phi);

        writeKey(privOut,  d, n);
        writeKey(pubOut,   e, n);
        writePrimes(primesOut, p, q);
        if (verifyKeyPair(e, d, p, q)) {
            System.out.println("Key-Paar ist gültig.");
        } else {
            System.out.println("Warnung: e*d mod φ(n) ≠ 1 !");
        }
    }

    private static BigInteger generatePrime(int bitLength) {
        int zBits = bitLength - 5;
        while (true) {
            BigInteger z = new BigInteger(zBits, random).abs();
            for (int offset : OFFSETS) {
                BigInteger cand = z.multiply(BigInteger.valueOf(30))
                        .add(BigInteger.valueOf(offset));
                if (cand.bitLength() != bitLength) continue;
                if (isProbablePrime(cand, 40)) return cand;
            }
        }
    }

    private static boolean isProbablePrime(BigInteger n, int rounds) {
        if (n.compareTo(BigInteger.TWO) < 0) return false;
        if (n.equals(BigInteger.TWO)) return true;
        if (n.mod(BigInteger.TWO).equals(BigInteger.ZERO)) return false;

        BigInteger m = n.subtract(BigInteger.ONE);
        int k = m.getLowestSetBit();
        m = m.shiftRight(k);

        for (int i = 0; i < rounds; i++) {
            BigInteger a = new BigInteger(n.bitLength(), random)
                    .mod(n.subtract(BigInteger.valueOf(4)))
                    .add(BigInteger.TWO);
            BigInteger b = a.modPow(m, n);
            if (b.equals(BigInteger.ONE) || b.equals(n.subtract(BigInteger.ONE)))
                continue;
            boolean next = false;
            for (int j = 1; j < k; j++) {
                b = b.multiply(b).mod(n);
                if (b.equals(n.subtract(BigInteger.ONE))) {
                    next = true;
                    break;
                }
            }
            if (!next) return false;
        }
        return true;
    }

    private static BigInteger modInverse(BigInteger a, BigInteger m) {
        BigInteger[] vals = extendedGCD(a, m);
        BigInteger g = vals[0], x = vals[1];
        if (!g.equals(BigInteger.ONE))
            throw new ArithmeticException("Kein Inverses, gcd ≠ 1");
        return x.mod(m);
    }

    private static BigInteger[] extendedGCD(BigInteger a, BigInteger b) {
        BigInteger x0 = BigInteger.ONE,  y0 = BigInteger.ZERO;
        BigInteger x1 = BigInteger.ZERO, y1 = BigInteger.ONE;
        while (!b.equals(BigInteger.ZERO)) {
            BigInteger[] dr = a.divideAndRemainder(b);
            BigInteger q = dr[0], r = dr[1];
            a = b;  b = r;
            BigInteger x2 = x0.subtract(q.multiply(x1));
            BigInteger y2 = y0.subtract(q.multiply(y1));
            x0 = x1; y0 = y1;
            x1 = x2; y1 = y2;
        }
        return new BigInteger[]{a, x0, y0};
    }

    private static void writeKey(Path path, BigInteger exp, BigInteger n) throws IOException {
        if (path.getParent() != null) Files.createDirectories(path.getParent());
        List<String> lines = List.of(exp.toString(), n.toString());
        Files.write(path, lines);
    }

    private static void writePrimes(Path path, BigInteger p, BigInteger q) throws IOException {
        if (path.getParent() != null) Files.createDirectories(path.getParent());
        List<String> lines = List.of(p.toString(), q.toString());
        Files.write(path, lines);
    }

    /**
     * Überprüft, ob e * d ≡ 1 mod φ(n), mit φ(n) = (p-1)*(q-1).
     *
     * @param e öffentlicher Exponent
     * @param d privater Exponent
     * @param p erste Primzahl
     * @param q zweite Primzahl
     * @return true, falls e*d % ((p-1)*(q-1)) == 1
     */
    public static boolean verifyKeyPair(BigInteger e,
                                        BigInteger d,
                                        BigInteger p,
                                        BigInteger q) {
        // φ(n) = (p-1)*(q-1)
        BigInteger phi = p.subtract(BigInteger.ONE)
                .multiply(q.subtract(BigInteger.ONE));
        // e*d mod φ(n)
        BigInteger edModPhi = e.multiply(d).mod(phi);
        // true, wenn edModPhi == 1
        return edModPhi.equals(BigInteger.ONE);
    }
}
