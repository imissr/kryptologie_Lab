package org.example.sha;

import java.io.*;
import java.util.Arrays;

public class SHA {
    // Keccak-f[1600] parameters
    private static final int b = 1600;
    private static final int w = 64;           // lane size in bits
    private static final int l = 6;            // log2(w)
    private static final int nr = 12 + 2 * l;  // number of rounds = 24

    private final int capacity;   // in bits
    private final int rate;       // in bits
    private final int outputBits; // digest length in bits
    private long[][] S;           // 5x5 state of 64-bit lanes

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
            0x01L, 0x8082L, 0x800000000000808aL,
            0x8000000080008000L, 0x808bL, 0x80000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x8aL,
            0x88L, 0x80008009L, 0x8000000aL,
            0x8000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x80000001L, 0x8000000080008008L,
    };

    // Default: SHA3-224
    public SHA() {
        this(448, 224);
    }

    // For other SHA3 variants: outputBits in {224, 256, 384, 512}; capacity = 2*outputBits
    public SHA(int capacity, int outputBits) {
        this.capacity = capacity;
        this.rate = b - capacity;
        this.outputBits = outputBits;
        this.S = new long[5][5];
    }

    // SHA-3 padding: suffix 0x06, then pad10*1 (last bit 0x80)
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
        for (int y = 0; y < 5; y++) {           // fix: iterate rows (fixed y)
            long[] T = new long[5];
            for (int x = 0; x < 5; x++) T[x] = S[x][y];
            for (int x = 0; x < 5; x++) {
                S[x][y] ^= (~T[(x + 1) % 5]) & T[(x + 2) % 5];
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
                int laneIndex = i / 8;      // 0..(rate/64 - 1)
                int x = laneIndex % 5;
                int y = laneIndex / 5;
                int shift = (i % 8) * 8;    // LE inside the 64-bit lane
                S[x][y] ^= ((long)(padded[offset + i] & 0xFF)) << shift;
            }
            keccakF();
        }
    }
    private byte[] squeeze() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int lanesInRate = rate / w; // number of 64-bit lanes in the rate
        while (baos.size() * 8 < outputBits) {
            int producedLanes = 0;
            for (int y = 0; y < 5 && producedLanes < lanesInRate; y++) {
                for (int x = 0; x < 5 && producedLanes < lanesInRate; x++) {
                    long lane = S[x][y];
                    for (int i = 0; i < 8; i++) {
                        baos.write((int)((lane >>> (8 * i)) & 0xFF));
                    }
                    producedLanes++;
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

    // Utility: hex string to byte[] ignoring whitespace; odd-length auto-pad
    private static byte[] hexToBytes(String hex) {
        if (hex == null) return new byte[0];
        hex = hex.replaceAll("\\s+", "");
        if (hex.isEmpty()) return new byte[0];
        if (hex.length() % 2 != 0) hex = "0" + hex;
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int hi = Character.digit(hex.charAt(i), 16);
            int lo = Character.digit(hex.charAt(i + 1), 16);
            if (hi == -1 || lo == -1) {
                throw new IllegalArgumentException("Invalid hex character at position " + i + ".");
            }
            data[i / 2] = (byte) ((hi << 4) + lo);
        }
        return data;
    }

    public static void main(String[] args) throws IOException {
        if (args.length != 2) {
            System.err.println("Usage: java org.example.sha.SHA <inputHexFile> <outputDigestFile>");
            System.exit(1);
        }
        String inputFile = args[0];
        String outputFile = args[1];

        // Read entire file (may be empty or multi-line); treat empty as empty message
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(inputFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append('\n');
            }
        }
        String hexInput = sb.toString();
        byte[] message = hexToBytes(hexInput); // returns empty array for empty/whitespace

        SHA sha3_224 = new SHA(); // default: capacity=448, outputBits=224
        String digest = sha3_224.hexdigest(message);

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {
            writer.write(digest);
            writer.newLine();
        }

        System.out.println(digest);
    }
}
