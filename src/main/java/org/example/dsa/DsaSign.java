package org.example.dsa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.example.rsa.RSA;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;

public class DsaSign {
    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("Usage: java DsaSign <privateKeyFile> <messageFile> <signatureFile>");
            System.exit(1);
        }
        Security.addProvider(new BouncyCastleProvider());
        String privFile = "src/main/java/org/example/dsa/" + args[0];
        String msgFile = "src/main/java/org/example/dsa/" + args[1];
        String sigFile = "src/main/java/org/example/dsa/" + args[2];
        sign(privFile, msgFile, sigFile);
    }



    private static void sign(String privFile, String msgFile, String sigFile) throws Exception {
        BufferedReader in = new BufferedReader(new FileReader(privFile));

        BigInteger p = new BigInteger(in.readLine().trim());
        BigInteger q = new BigInteger(in.readLine().trim());
        BigInteger g = new BigInteger(in.readLine().trim());
        BigInteger x = new BigInteger(in.readLine().trim());
        in.close();

        String message = new String(Files.readAllBytes(Paths.get(msgFile)), StandardCharsets.UTF_8);
        MessageDigest md = MessageDigest.getInstance("SHA-224", "BC");
        BigInteger H = new BigInteger(1, md.digest(message.getBytes(StandardCharsets.UTF_8)));

        SecureRandom rand = new SecureRandom();
        BigInteger k, r, s;
        while (true) {
            do {
                k = new BigInteger(q.bitLength(), rand);
            } while (k.compareTo(BigInteger.ONE) <= 0 || k.compareTo(q) >= 0);
            BigInteger temp = RSA.modPow(g, k, p);
            r = temp.mod(q);
            if (r.equals(BigInteger.ZERO)) continue;

            BigInteger kInv = k.modInverse(q);
            s = kInv.multiply(H.add(r.multiply(x))).mod(q);
            if (!s.equals(BigInteger.ZERO)) break;
        }

        try (BufferedWriter out = new BufferedWriter(new FileWriter(sigFile))) {
            out.write(r.toString()); out.newLine();
            out.write(s.toString()); out.newLine();
        }

        System.out.println("Signature written to " + sigFile);
    }
}


