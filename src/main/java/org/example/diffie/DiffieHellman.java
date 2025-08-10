package org.example.diffie;

import org.example.rsa.RSA;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Utility class for Diffie-Hellman operations and safe-prime generation.
 */
public class DiffieHellman {
    private static final SecureRandom random = new SecureRandom();
    private static final int[] OFFSETS = {1, 7, 11, 13, 17, 19, 23, 29};

    /**
     * Generates a random prime of specified bit length using a 30k ± offsets method.
     * @param bitLength desired bit-length of the prime
     * @return a probable prime of that bit-length
     */
    public static BigInteger generatePrime(int bitLength) {
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
     * Miller-Rabin primality test.
     * @param n candidate
     * @param rounds number of bases to test
     */
    public static boolean isProbablePrime(BigInteger n, int rounds) {
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
            BigInteger b = RSA.modPow(a, m, n);
            if (b.equals(BigInteger.ONE) || b.equals(n.subtract(BigInteger.ONE)))
                continue;
            boolean nextRound = false;
            for (int j = 1; j < k; j++) {
                b = b.multiply(b).mod(n);
                if (b.equals(n.subtract(BigInteger.ONE))) {
                    nextRound = true;
                    break;
                }
            }
            if (!nextRound) return false;
        }
        return true;
    }

    /**
     * Generates a safe prime p = 2q + 1 of given bit length using custom prime generation.
     */
    public static BigInteger generateSafePrime(int bits) {
        BigInteger q;
        BigInteger p;
        do {
            q = generatePrime(bits - 1);
            p = q.shiftLeft(1).add(BigInteger.ONE);
        } while (!isProbablePrime(p, 40));
        return p;
    }

    /**
     * Picks a generator g (of large order) modulo p. For safe-prime p=2q+1,
     * any g with g^q mod p != 1 and g^2 mod p != 1 has order 2q.
     */
    public static BigInteger pickGenerator(BigInteger p) {
        BigInteger q = p.subtract(BigInteger.ONE).shiftRight(1);
        BigInteger g;
        do {
            g = new BigInteger(p.bitLength(), random)
                    .mod(p.subtract(BigInteger.TWO)).add(BigInteger.TWO);
        } while (RSA.modPow(g,BigInteger.TWO , p).equals(BigInteger.ONE)||
                RSA.modPow(g, q, p).equals(BigInteger.ONE));
        return g;
    }

    /**
     * Computes public value g^secret mod p.
     */
    public static BigInteger computePublic(BigInteger g, BigInteger secret, BigInteger p) {
        return RSA.modPow(g,secret, p) ;
    }

    /**
     * Computes shared secret otherPub^secret mod p.
     */
    public static BigInteger computeSharedSecret(BigInteger otherPub, BigInteger secret, BigInteger p) {
        return RSA.modPow(otherPub,secret,p);
    }

    // Prevent instantiation
    private DiffieHellman() { }


    /**
     * Validates a complete Diffie-Hellman exchange.
     * @param p prime
     * @param g generator
     * @param a Alice's secret exponent
     * @param b Bob's secret exponent
     * @param A Alice's public value
     * @param B Bob's public value
     * @param S shared secret
     * @return true if A = g^a mod p, B = g^b mod p, and S = B^a mod p = A^b mod p
     */
    public static boolean validateExchange(BigInteger p, BigInteger g,
                                           BigInteger a, BigInteger b,
                                           BigInteger A, BigInteger B,
                                           BigInteger S) {
        // Check public values
        if (!A.equals(g.modPow(a, p))) return false;
        if (!B.equals(g.modPow(b, p))) return false;
        // Check shared secret consistency
        BigInteger s1 = B.modPow(a, p);
        BigInteger s2 = A.modPow(b, p);
        return S.equals(s1) && S.equals(s2);
    }
}