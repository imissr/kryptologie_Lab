package org.example.diffie;

import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;

public class DHParamGenerator {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: java diffie.DHParamGenerator <bitlength>");
            System.exit(1);
        }
        int bits;
        try {
            bits = Integer.parseInt(args[0]);
        } catch (NumberFormatException e) {
            System.err.println("Error: Bit length must be an integer.");
            return;
        }

        // Generate safe prime p and generator g
        BigInteger p = DiffieHellman.generateSafePrime(bits);
        BigInteger g = DiffieHellman.pickGenerator(p);

        // Write parameters to a text file
        try (FileWriter writer = new FileWriter("diffie/dhparams.txt")) {
            writer.write(p.toString());
            writer.write(System.lineSeparator());
            writer.write(g.toString());
            System.out.println("DH parameters successfully written to dhparams.txt");
        } catch (IOException e) {
            System.err.println("Failed to write DH parameters: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
