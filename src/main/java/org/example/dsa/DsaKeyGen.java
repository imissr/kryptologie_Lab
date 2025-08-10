package org.example.dsa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.example.diffie.DiffieHellman;
import org.example.rsa.RSA;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;

public class DsaKeyGen {
    // Key sizes
    private static final int L = 1024; // p bit-length
    private static final int N = 160;  // q bit-length

    public static void main(String[] args) throws IOException {
        if (args.length != 2) {
            System.err.println("Usage: java DsaKeyGen <publicKeyFile> <privateKeyFile>");
            System.exit(1);
        }
        String pubFile = "src/main/java/org/example/dsa/" + args[0];
        String privFile = "src/main/java/org/example/dsa/" + args[1];

        // Only generate if key files do not already exist
        File pub = new File(pubFile);
        File priv = new File(privFile);
        if (pub.exists() && priv.exists()) {
            System.out.println("Key files already exist; generation skipped.");
            return;
        }

        // Ensure parent directories exist
        File pubDir = pub.getParentFile();
        if (pubDir != null && !pubDir.exists()) {
            pubDir.mkdirs();
        }
        File privDir = priv.getParentFile();
        if (privDir != null && !privDir.exists()) {
            privDir.mkdirs();
        }

        Security.addProvider(new BouncyCastleProvider());
        generateKeys(pubFile, privFile);
    }

    private static void generateKeys(String pubFile, String privFile) throws IOException {
        SecureRandom rand = new SecureRandom();

        // 1. Generate prime q using custom implementation
        BigInteger q = DiffieHellman.generatePrime(N);
        //or : BigInteger q = BigInteger.probablePrime(N, rand);

        // 2. Generate p = k*q + 1, prime of bit-length L
        BigInteger p, k;
        do {
            // k is (L-N)-bit random with MSB set
            k = new BigInteger(L - N, rand).setBit(L - N - 1);
            p = q.multiply(k).add(BigInteger.ONE);
        } while (!DiffieHellman.isProbablePrime(p, 40) || p.bitLength() != L);

        // 3. Find generator g of order q
        BigInteger h, g;
        do {
            h = new BigInteger(L, rand)
                    .mod(p.subtract(BigInteger.TWO))
                    .add(BigInteger.TWO);
            g = RSA.modPow(h,k,p);
        } while (g.compareTo(BigInteger.ONE) <= 0);

        // 4. Private key x
        BigInteger x;
        do {
            x = new BigInteger(N, rand);
        } while (x.compareTo(BigInteger.ONE) <= 0 || x.compareTo(q) >= 0);

        // 5. Public key y = g^x mod p
        BigInteger y = RSA.modPow(g,x,p);

        // Write public key (p, q, g, y)
        try (BufferedWriter out = new BufferedWriter(new FileWriter(pubFile))) {
            System.out.println("Writing public key to: " + pubFile);
            out.write(p.toString()); out.newLine();
            out.write(q.toString()); out.newLine();
            out.write(g.toString()); out.newLine();
            out.write(y.toString()); out.newLine();
        }

        // Write private key (p, q, g, x)
        try (BufferedWriter out = new BufferedWriter(new FileWriter(privFile))) {
            System.out.println("Writing private key to: " + privFile);
            out.write(p.toString()); out.newLine();
            out.write(q.toString()); out.newLine();
            out.write(g.toString()); out.newLine();
            out.write(x.toString()); out.newLine();
        }

        System.out.println("Keys generated successfully.");
    }
}
