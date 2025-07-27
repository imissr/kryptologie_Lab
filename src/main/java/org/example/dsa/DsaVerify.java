package org.example.dsa;// File: DsaVerify.java

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.Security;


public class DsaVerify {
    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("Usage: java DsaVerify <publicKeyFile> <messageFile> <signatureFile>");
            System.exit(1);
        }
        Security.addProvider(new BouncyCastleProvider());
        String pubFile = "src/main/java/org/example/dsa/" + args[0];
        String msgFile = "src/main/java/org/example/dsa/" + args[1];
        String sigFile = "src/main/java/org/example/dsa/" + args[2];
        verify(pubFile, msgFile, sigFile);
    }

    private static void verify(String pubFile, String msgFile, String sigFile) throws Exception {
        BufferedReader in = new BufferedReader(new FileReader(pubFile));
        BigInteger p = new BigInteger(in.readLine());
        BigInteger q = new BigInteger(in.readLine());
        BigInteger g = new BigInteger(in.readLine());
        BigInteger y = new BigInteger(in.readLine());
        in.close();

        String message = new String(Files.readAllBytes(Paths.get(msgFile)), StandardCharsets.UTF_8);
        MessageDigest md = MessageDigest.getInstance("SHA-224", "BC");
        BigInteger H = new BigInteger(1, md.digest(message.getBytes(StandardCharsets.UTF_8)));

        BufferedReader sigIn = new BufferedReader(new FileReader(sigFile));
        BigInteger r = new BigInteger(sigIn.readLine());
        BigInteger s = new BigInteger(sigIn.readLine());
        sigIn.close();

        if (r.compareTo(BigInteger.ONE) < 0 || r.compareTo(q) >= 0 ||
                s.compareTo(BigInteger.ONE) < 0 || s.compareTo(q) >= 0) {
            System.out.println("Signature invalid");
            return;
        }

        BigInteger w = s.modInverse(q);
        BigInteger u1 = H.multiply(w).mod(q);
        BigInteger u2 = r.multiply(w).mod(q);
        BigInteger v = g.modPow(u1, p)
                .multiply(y.modPow(u2, p))
                .mod(p)
                .mod(q);

        System.out.println(v.equals(r) ? "Signature valid" : "Signature invalid");
    }
}