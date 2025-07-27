package org.example.lineareAnalysis;

import org.example.lineareAnalysis.Spn;

import java.io.*;
import java.util.*;

public class LinApprox {
    private static final String[] SBOX = {"1110","0100","1101","0001","0010","1111","1011","1000","0011","1010","0110","1100","0101","1001","0000","0111"};
    private static final String[] INV_SBOX = new String[16];


    static {
        // Compute inverse S-box
        for (int i = 0; i < 16; i++) {
            String code = intTo4BitBinary(i);
            for (int j = 0; j < 16; j++) {
                if (SBOX[j].equals(code)) {
                    INV_SBOX[i] = intTo4BitBinary(j);
                    break;
                }
            }
        }
    }

    // XOR multiple single-bit strings or equal-length bit-strings
    public static String xor(String... args) {
        int len = args[0].length();
        StringBuilder sb = new StringBuilder();
        // If single-bit strings
        if (len == 1) {
            int sum = 0;
            for (String s : args) sum += Integer.parseInt(s);
            sb.append(sum % 2);
        } else {
            // Bitwise XOR for multi-bit strings
            for (int i = 0; i < len; i++) {
                int sum = 0;
                for (String s : args) sum += (s.charAt(i) - '0');
                sb.append(sum % 2);
            }
        }
        return sb.toString();
    }

    // Convert hex string to binary
    public static String hexToBinary(String hex) {
        StringBuilder sb = new StringBuilder();
        for (char c : hex.toCharArray()) {
            int v = Character.digit(c, 16);
            if (v >= 0) sb.append(String.format("%4s", Integer.toBinaryString(v)).replace(' ', '0'));
        }
        return sb.toString();
    }

    // Convert binary string to hex string
    public static String binaryToHex(String bin) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bin.length(); i += 4) {
            String nibble = bin.substring(i, i + 4);
            sb.append(Integer.toHexString(Integer.parseInt(nibble, 2)).toUpperCase());
        }
        return sb.toString();
    }

    public static int binaryToInt(String bin) {
        return Integer.parseInt(bin, 2);
    }

    public static String intTo4BitBinary(int i) {
        return String.format("%4s", Integer.toBinaryString(i)).replace(' ', '0');
    }

    // Call SPN implementation for encryption
    public static String encrypt(String inputHex, String keyHex) {
        return Spn.encrypt(inputHex, keyHex);
    }

    // Generate plaintext/ciphertext pairs using a provided SPN key
    public static void generatePairs(String plainFile, String cipherFile, int numPairs, String keyHex) throws IOException {
        Random rand = new Random();
        System.out.println("Using SPN key: " + keyHex);

        try (BufferedWriter pw = new BufferedWriter(new FileWriter(plainFile));
             BufferedWriter cw = new BufferedWriter(new FileWriter(cipherFile))) {
            for (int i = 0; i < numPairs; i++) {
                int pt = rand.nextInt(1 << 16);
                String pbin = String.format("%16s", Integer.toBinaryString(pt)).replace(' ', '0');
                String phex = binaryToHex(pbin);
                String chex = encrypt(phex, keyHex);
                pw.write(phex);
                pw.newLine();
                cw.write(chex);
                cw.newLine();
            }
        }
    }

    // Linear cryptanalysis to recover two 4-bit subkey nibbles
    public static Pair<String, String> getMaxKey(List<Pair<String, String>> M) {
        double half = M.size() / 2.0;
        int[] alpha = new int[256];
        for (Pair<String, String> pair : M) {
            String x = pair.first;
            String y = pair.second;
            for (int j = 0; j < 256; j++) {
                String L1 = intTo4BitBinary(j % 16);
                String L2 = intTo4BitBinary(j / 16);
                String v2 = xor(L1, y.substring(4, 8));
                String v4 = xor(L2, y.substring(12, 16));
                String u2 = INV_SBOX[binaryToInt(v2)];
                String u4 = INV_SBOX[binaryToInt(v4)];
                String cond = xor(
                        String.valueOf(x.charAt(4)),
                        String.valueOf(x.charAt(6)),
                        String.valueOf(x.charAt(7)),
                        String.valueOf(u2.charAt(1)),
                        String.valueOf(u2.charAt(3)),
                        String.valueOf(u4.charAt(1)),
                        String.valueOf(u4.charAt(3))
                );
                if ("0".equals(cond)) alpha[j]++;
            }
        }
        double maxB = -1;
        String bestL1 = null, bestL2 = null;
        for (int j = 0; j < 256; j++) {
            double bias = Math.abs(alpha[j] - half);
            if (bias > maxB) {
                maxB = bias;
                bestL1 = intTo4BitBinary(j % 16);
                bestL2 = intTo4BitBinary(j / 16);
            }
        }
        return new Pair<>(bestL1, bestL2);
    }

    /**
     * Perform linear approximation on given plaintext and ciphertext files.
     * Reads the files, recovers the key, and writes to outFile if provided.
     */
    public static void performLinearApproximation(String plainFile, String cipherFile, String outFile) throws IOException {
        List<String> plains = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(plainFile))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) plains.add(hexToBinary(line));
            }
        }
        List<String> ciphers = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(cipherFile))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) ciphers.add(hexToBinary(line));
            }
        }
        if (plains.size() != ciphers.size()) {
            System.err.println("Mismatch between number of plaintexts and ciphertexts");
            return;
        }
        List<Pair<String, String>> M = new ArrayList<>();
        for (int i = 0; i < plains.size(); i++) {
            M.add(new Pair<>(plains.get(i), ciphers.get(i)));
        }
        Pair<String, String> maxKey = getMaxKey(M);
        String resultKey = binaryToHex(maxKey.first + maxKey.second);
        if (outFile != null) {
            try (BufferedWriter bw = new BufferedWriter(new FileWriter(outFile))) {
                bw.write(resultKey);
            }
        }
        System.out.println("Recovered key: " + resultKey);
    }

    public static void main(String[] args) throws IOException {
        if (args.length > 0 && "generate".equalsIgnoreCase(args[0])) {
            if (args.length != 5) {
                System.out.println("Usage: java LinApprox generate plaintextFile ciphertextFile numPairs keyHex");
                return;
            }
            String plainFile = args[1];
            String cipherFile = args[2];
            int n = Integer.parseInt(args[3]);
            String keyHex = args[4];
            generatePairs(plainFile, cipherFile, n, keyHex);
        } else if (args.length == 2 || args.length == 3) {
            String plainFile = args[0];
            String cipherFile = args[1];
            String outFile = args.length == 3 ? args[2] : null;
            performLinearApproximation(plainFile, cipherFile, outFile);
        } else {
            System.out.println("Usage:");
            System.out.println("  To generate: java LinApprox generate plaintextFile ciphertextFile numPairs keyHex");
            System.out.println("  To analyze: java LinApprox plaintexts.txt ciphertexts.txt [output_file]");
        }
    }

    // Simple Pair class
    public static class Pair<A, B> {
        public final A first;
        public final B second;
        public Pair(A first, B second) {this.first = first; this.second = second;}
    }
}