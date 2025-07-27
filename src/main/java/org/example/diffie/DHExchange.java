package org.example.diffie;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

public class DHExchange {
    public static void main(String[] args) {
        BigInteger p = null, g = null;

        // Automatically read parameters p and g from dhparams.txt
        try (BufferedReader reader = new BufferedReader(new FileReader("diffie/dhparams.txt"))) {
            String pLine = reader.readLine();
            String gLine = reader.readLine();
            if (pLine == null || gLine == null) {
                System.err.println("Error: dhparams.txt must contain two lines (p and g)");
                return;
            }
            p = new BigInteger(pLine.trim());
            g = new BigInteger(gLine.trim());
        } catch (IOException e) {
            System.err.println("Failed to read parameters: " + e.getMessage());
            e.printStackTrace();
            return;
        }

        // Generate secrets a and b
        SecureRandom rnd = new SecureRandom();
        BigInteger a = new BigInteger(p.bitLength() - 2, rnd);
        BigInteger b = new BigInteger(p.bitLength() - 2, rnd);

        // Compute public values A and B
        BigInteger A = DiffieHellman.computePublic(g, a, p);
        BigInteger B = DiffieHellman.computePublic(g, b, p);

        // Compute shared secret S
        BigInteger S = DiffieHellman.computeSharedSecret(B, a, p);

        // Validate the exchange
        boolean valid = DiffieHellman.validateExchange(p, g, a, b, A, B, S);

        // Output to console
        System.out.println("A=" + A);
        System.out.println("B=" + B);
        System.out.println("SharedSecret=" + S);
        System.out.println("Valid exchange? " + valid);

        // Write results to a text file
        try (FileWriter writer = new FileWriter("diffie/dhexchange.txt")) {
            writer.write("A=" + A.toString());
            writer.write(System.lineSeparator());
            writer.write("B=" + B.toString());
            writer.write(System.lineSeparator());
            writer.write("SharedSecret=" + S.toString());
            writer.write(System.lineSeparator());
            writer.write("ValidExchange=" + valid);
            writer.write(System.lineSeparator());
            System.out.println("Exchange results successfully written to dhexchange.txt");
        } catch (IOException e) {
            System.err.println("Failed to write exchange results: " + e.getMessage());
            e.printStackTrace();
        }
    }
}