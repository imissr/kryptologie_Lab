package org.example.sha;

import java.io.*;
import java.util.Arrays;

public class SHA {
    // Keccak-f[1600] parameters
    private static final int b = 1600;
    private static final int w = 64;            // lane size in bits
    private static final int l = 6;             // log2(w)
    private static final int nr = 12 + 2 * l;   // number of rounds = 24

    private final int capacity;  // in bits
    private final int rate;      // in bits
    private final int outputBits;
    private long[][] S;          // 5x5 state of 64-bit lanes

    // Rotation offsets (rho)
    private static final int[][] rhoOffsets = {
            { 0, 36,  3, 41, 18},
            { 1, 44, 10, 45,  2},
            {62,  6, 43, 15, 61},
            {28, 55, 25, 21, 56},
            {27, 20, 39,  8, 14}
    };

    // Round constants
    private static final long[] RC = {
            0x0000000000000001L, 0x0000000000008082L,
            0x800000000000808AL, 0x8000000080008000L,
            0x000000000000808BL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L,
            0x000000000000008AL, 0x0000000000000088L,
            0x0000000080008009L, 0x000000008000000AL,
            0x000000008000808BL, 0x800000000000008BL,
            0x8000000000008089L, 0x8000000000008003L,
            0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800AL, 0x800000008000000AL,
            0x8000000080008081L, 0x8000000000008080L,
            0x0000000080000001L, 0x8000000080008008L
    };

    public SHA() {
        this(448, 224);
    }

    public SHA(int capacity, int outputBits) {
        this.capacity = capacity;
        this.rate = b - capacity;
        this.outputBits = outputBits;
        this.S = new long[5][5];
    }

    private byte[] pad(byte[] message) {
        int rateBytes = rate / 8;
        int padLen = rateBytes - (message.length % rateBytes);
        if (padLen == 0) padLen = rateBytes;
        byte[] padding = new byte[padLen];
        padding[0] = 0x06;
        padding[padLen - 1] |= (byte) 0x80;
        byte[] result = new byte[message.length + padLen];
        System.arraycopy(message, 0, result, 0, message.length);
        System.arraycopy(padding, 0, result, message.length, padLen);
        return result;
    }

    private void keccakF() {
        for (int round = 0; round < nr; round++) {
            theta(); rho(); pi(); chi(); iota(round);
        }
    }

    private void theta() {
        long[] C = new long[5];
        long[] D = new long[5];
        for (int x = 0; x < 5; x++) {
            C[x] = S[x][0] ^ S[x][1] ^ S[x][2] ^ S[x][3] ^ S[x][4];
        }
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ Long.rotateLeft(C[(x + 1) % 5], 1);
        }
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                S[x][y] ^= D[x];
            }
        }
    }

    private void rho() {
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                S[x][y] = Long.rotateLeft(S[x][y], rhoOffsets[x][y]);
            }
        }
    }

    private void pi() {
        long[][] B = new long[5][5];
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                B[y][(2 * x + 3 * y) % 5] = S[x][y];
            }
        }
        S = B;
    }

    private void chi() {
        for (int x = 0; x < 5; x++) {
            long[] T = Arrays.copyOf(S[x], 5);
            for (int y = 0; y < 5; y++) {
                S[x][y] ^= (~T[(y + 1) % 5]) & T[(y + 2) % 5];
            }
        }
    }

    private void iota(int round) {
        S[0][0] ^= RC[round];
    }

    private void absorb(byte[] padded) {
        int blockSize = rate / 8;
        for (int offset = 0; offset < padded.length; offset += blockSize) {
            for (int i = 0; i < blockSize; i++) {
                int x = (i * 8 / 64) % 5;
                int y = (i * 8 / 64) / 5;
                int shift = (i % 8) * 8;
                S[x][y] ^= (long) (padded[offset + i] & 0xFF) << shift;
            }
            keccakF();
        }
    }

    private byte[] squeeze() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int blockSize = rate / 8;
        while (baos.size() * 8 < outputBits) {
            for (int y = 0; y < 5; y++) {
                for (int x = 0; x < 5; x++) {
                    if ((5 * y + x) * w < rate) {
                        long lane = S[x][y];
                        for (int i = 0; i < 8; i++) {
                            baos.write((int) ((lane >>> (8 * i)) & 0xFF));
                        }
                    }
                }
            }
            if (baos.size() * 8 >= outputBits) break;
            keccakF();
        }
        byte[] full = baos.toByteArray();
        return Arrays.copyOf(full, outputBits / 8);
    }

    public byte[] hash(byte[] message) {
        byte[] padded = pad(message);
        absorb(padded);
        return squeeze();
    }

    public String hexdigest(byte[] message) {
        byte[] digest = hash(message);
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    // Utility: hex string to byte[] ignoring whitespace and odd-length auto-pad
    /*private static byte[] hexToBytes(String hex) {
        // Remove all whitespace
        hex = hex.replaceAll("\\s+", "");
        // If odd length, prepend '0'
        if (hex.length() % 2 != 0) {
            hex = "0" + hex;
        }
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int hi = Character.digit(hex.charAt(i), 16);
            int lo = Character.digit(hex.charAt(i + 1), 16);
            if (hi == -1 || lo == -1) {
                throw new IllegalArgumentException(
                        "Invalid hex character at position " + i + ".");
            }
            data[i / 2] = (byte) ((hi << 4) + lo);
        }
        return data;
    }*/

    // Utility: hex string to byte[]
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }

    public static void main(String[] args) throws IOException {
        if (args.length != 2) {
            System.err.println("Usage: java ShaMain <inputHexFile> <outputDigestFile>");
            System.exit(1);
        }
        String inputFile = args[0];
        String outputFile = args[1];

        String hexInput;
        try (BufferedReader reader = new BufferedReader(new FileReader(inputFile))) {
            hexInput = reader.readLine().trim();
        }
        byte[] message = hexToBytes(hexInput);
        SHA sha = new SHA();
        String digest = sha.hexdigest(message);

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {
            writer.write(digest);
            writer.newLine();
        }

        System.out.println(digest);
    }
}
