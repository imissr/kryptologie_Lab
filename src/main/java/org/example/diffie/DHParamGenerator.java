package org.example.diffie;

import java.io.File;
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

        try {
            // Create the directory if it doesn't exist
            File diffieDir = new File("src/main/java/org/example/diffie");
            if (!diffieDir.exists()) {
                diffieDir.mkdirs();
                System.out.println("Created directory: " + diffieDir.getPath());
            }

            // Write to the file inside the diffie directory
            try (FileWriter writer = new FileWriter("src/main/java/org/example/diffie/dhparams.txt")) {
                writer.write(p.toString());
                writer.write(System.lineSeparator());
                writer.write(g.toString());
                System.out.println("DH parameters successfully written to src/main/java/org/example/diffie/dhparams.txt");
            }
        } catch (IOException e) {
            System.err.println("Failed to write DH parameters: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
