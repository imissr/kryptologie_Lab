package org.example.rsa;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.List;

/**
 * Simple RSA key generator.
 *
 * <p>Generates two primes {@code p} and {@code q} using the Miller–Rabin test,
 * uses a 30-wheel ({@link #OFFSETS}) to find candidates efficiently, and then computes:
 * {@code n = p*q}, {@code φ = (p-1)(q-1)}, a random public exponent {@code e}
 * with {@code gcd(e, φ) = 1}, and the private exponent {@code d = e^{-1} mod φ}.</p>
 *
 * <p>Outputs:
 * <ul>
 *   <li>Private key: {@code (d, n)}</li>
 *   <li>Public key: {@code (e, n)}</li>
 *   <li>Primes: {@code p} and {@code q}</li>
 * </ul>
 * </p>
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * java org.example.rsa.RSAKeygenerator <bitLength> <privOut> <pubOut> <primesOut>
 * }</pre>
 *
 * <p><b>Note:</b> For learning/demo purposes only. No side-channel hardening or secure key storage.</p>
 *
 * @since 1.0
 */
public class RSAKeygenerator {
    private static final SecureRandom random = new SecureRandom();

    /** Offsets for the 30-wheel (skips multiples of 2, 3, and 5). */
    private static final int[] OFFSETS = {1, 7, 11, 13, 17, 19, 23, 29};

    /**
     * CLI entry point.
     *
     * @param args Four arguments: {@code bitLength} {@code privOut} {@code pubOut} {@code primesOut}
     *             (see the usage example in the class Javadoc)
     */
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
     * Generates an RSA key pair with a random {@code e} and writes:
     * the private key ({@code d, n}), the public key ({@code e, n}),
     * and the primes {@code p, q} to the given files.
     *
     * @param bitLength bit length for primes {@code p} and {@code q}
     * @param privOut   output path for the private key ({@code d, n})
     * @param pubOut    output path for the public key ({@code e, n})
     * @param primesOut output path for the primes {@code p, q}
     * @throws IOException if any file cannot be written
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
            // Random in [2, phi-1]
            e = new BigInteger(phi.bitLength(), random)
                    .mod(phi.subtract(BigInteger.TWO))  // now [0, phi-3]
                    .add(BigInteger.TWO);               // now [2, phi-1]
        } while (!phi.gcd(e).equals(BigInteger.ONE));

        BigInteger d = modInverse(e, phi);

        writeKey(privOut,  d, n);
        writeKey(pubOut,   e, n);
        writePrimes(primesOut, p, q);
        if (verifyKeyPair(e, d, p, q)) {
            System.out.println("Key pair is valid.");
        } else {
            System.out.println("Warning: e*d mod φ(n) ≠ 1 !");
        }
    }

    /**
     * Generates a (probable) prime of the requested bit length.
     * <p>Strategy: produce candidates via the 30-wheel and test them with
     * {@link #isProbablePrime(BigInteger, int)} (40 rounds).</p>
     *
     * @param bitLength desired bit length of the prime
     * @return a {@link BigInteger} that is very likely prime
     */
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

    /**
     * Miller–Rabin primality test.
     *
     * @param n      number to test (n &gt;= 2)
     * @param rounds number of random bases (witnesses); more rounds → lower error probability
     * @return {@code true} if {@code n} is probably prime; otherwise {@code false}
     */
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

    /**
     * Computes the modular inverse of {@code a} modulo {@code m}
     * using the extended Euclidean algorithm.
     *
     * @param a value whose inverse is sought
     * @param m modulus (m &gt; 1)
     * @return {@code x} such that {@code a*x ≡ 1 (mod m)}
     * @throws ArithmeticException if {@code gcd(a, m) ≠ 1} (no inverse exists)
     */
    private static BigInteger modInverse(BigInteger a, BigInteger m) {
        BigInteger[] vals = extendedGCD(a, m);
        BigInteger g = vals[0], x = vals[1];
        if (!g.equals(BigInteger.ONE))
            throw new ArithmeticException("No inverse; gcd ≠ 1");
        return x.mod(m);
    }

    /**
     * Extended Euclidean algorithm.
     *
     * @param a first value
     * @param b second value
     * @return array {@code [g, x, y]} with {@code g = gcd(a, b)} and {@code a*x + b*y = g}
     */
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

    /**
     * Writes a key (exponent and modulus) line by line to a file.
     * Creates missing parent directories if needed.
     *
     * @param path output path
     * @param exp  exponent ({@code d} for private or {@code e} for public)
     * @param n    modulus
     * @throws IOException on I/O errors
     */
    private static void writeKey(Path path, BigInteger exp, BigInteger n) throws IOException {
        if (path.getParent() != null) Files.createDirectories(path.getParent());
        List<String> lines = List.of(exp.toString(), n.toString());
        Files.write(path, lines);
    }

    /**
     * Writes the primes {@code p} and {@code q} line by line to a file.
     * Creates missing parent directories if needed.
     *
     * @param path output path
     * @param p    first prime
     * @param q    second prime
     * @throws IOException on I/O errors
     */
    private static void writePrimes(Path path, BigInteger p, BigInteger q) throws IOException {
        if (path.getParent() != null) Files.createDirectories(path.getParent());
        List<String> lines = List.of(p.toString(), q.toString());
        Files.write(path, lines);
    }

    /**
     * Verifies {@code e * d ≡ 1 mod φ(n)} where {@code φ(n) = (p-1)*(q-1)}.
     *
     * @param e public exponent
     * @param d private exponent
     * @param p first prime
     * @param q second prime
     * @return {@code true} if {@code e*d % ((p-1)*(q-1)) == 1}, otherwise {@code false}
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
        // true iff edModPhi == 1
        return edModPhi.equals(BigInteger.ONE);
    }
}
