package org.example.sha;

import java.io.*;
import java.util.Arrays;

/**
 * <h1>SHA3 (Keccak-f[1600]) minimal implementation</h1>
 *
 * <p>A compact, educational Java implementation of the SHA-3 hash function family
 * based on the Keccak-f[1600] permutation. The instance is parameterized by
 * <em>capacity</em> (in bits) and the desired <em>outputBits</em> (digest length); the
 * <em>rate</em> is derived as {@code 1600 - capacity}. The default constructor creates
 * a SHA3-224 instance (capacity 448, output 224 bits).</p>
 *
 * <p>The implementation follows the sponge construction with the SHA-3 domain
 * separation suffix {@code 0x06} and uses the canonical {@code pad10*1}
 * padding (final bit {@code 0x80}). Absorption and squeezing are performed in
 * little-endian order within each 64-bit lane of the 5×5 state.</p>
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * // Programmatic usage
 * SHA sha3_256 = new SHA(512, 256); // SHA3-256
 * byte[] digest = sha3_256.hash("hello".getBytes(StandardCharsets.UTF_8));
 * String hex = sha3_256.hexdigest("hello".getBytes(StandardCharsets.UTF_8));
 *
 * // CLI
 * // Reads a file containing hex bytes (whitespace allowed) and writes digest hex
 * java org.example.sha.SHA <inputHexFile> <outputDigestFile>
 * }</pre>
 *
 * <h2>Implementation notes</h2>
 * <ul>
 *   <li>This code is designed for clarity and teaching, not constant-time
 *   operation or side-channel resistance.</li>
 *   <li>State lanes are 64-bit words; rotations use {@link Long#rotateLeft(long, int)}.</li>
 *   <li>Absorption maps the byte stream into lanes in little-endian order.</li>
 * </ul>
 *
 * @author Mohamad Khaled Minawe
 * @since 1.0
 */
public class SHA {
    /** Width of the Keccak state in bits (fixed for Keccak-f[1600]). */
    private static final int b = 1600;
    /** Lane size in bits (w = 2^l, here 64). */
    private static final int w = 64;           // lane size in bits
    /** log2(w) = 6 for 64-bit lanes. */
    private static final int l = 6;            // log2(w)
    /** Number of permutation rounds: nr = 12 + 2*l = 24. */
    private static final int nr = 12 + 2 * l;  // number of rounds = 24

    /** Sponge capacity in bits (2 × outputBits for SHA-3 variants). */
    private final int capacity;   // in bits
    /** Sponge rate in bits (b - capacity). */
    private final int rate;       // in bits
    /** Digest length in bits to be produced during squeeze. */
    private final int outputBits; // digest length in bits
    /** 5×5 Keccak state of 64-bit lanes (S[x][y]). */
    private long[][] S;           // 5x5 state of 64-bit lanes

    /**
     * Rotation offsets (ρ step) for each state lane S[x][y].
     * Indices follow Keccak's conventional (x, y) coordinates.
     */
    private static final int[][] rhoOffsets = {
            { 0, 36,  3, 41, 18},
            { 1, 44, 10, 45,  2},
            {62,  6, 43, 15, 61},
            {28, 55, 25, 21, 56},
            {27, 20, 39,  8, 14}
    };

    /**
     * Round constants (ι step) for Keccak-f[1600], applied to lane S[0][0].
     */
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

    /**
     * Creates a SHA3-224 hasher (capacity = 448 bits, output = 224 bits).
     */
    public SHA() {
        this(448, 224);
    }

    /**
     * Creates a SHA-3 variant with a given {@code capacity} and {@code outputBits}.
     * For the standard SHA-3 family, valid output sizes are 224, 256, 384, and 512 bits,
     * and {@code capacity} must be twice the output size.
     *
     * @param capacity   capacity in bits (typically {@code 2 * outputBits})
     * @param outputBits desired digest length in bits (e.g., 224, 256, 384, 512)
     * @throws IllegalArgumentException if parameters are non-positive or inconsistent
     */
    public SHA(int capacity, int outputBits) {
        this.capacity = capacity;
        this.rate = b - capacity;
        this.outputBits = outputBits;
        this.S = new long[5][5];
    }

    /**
     * Applies SHA-3 domain separation and Keccak padding to the message.
     * <p>Suffix {@code 0x06} is appended first, then pad10*1 with the final bit
     * {@code 0x80} so that the padded message is a multiple of {@code rate} bytes.</p>
     *
     * @param message input message bytes
     * @return a new byte array containing the padded message
     */
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

    /**
     * Applies the Keccak-f[1600] permutation with {@link #nr} rounds to the state.
     * Sequence: θ → ρ → π → χ → ι.
     */
    private void keccakF() {
        for (int round = 0; round < nr; round++) {
            theta(); rho(); pi(); chi(); iota(round);
        }
    }

    /** θ (theta) step: mixes columns to provide diffusion. */
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

    /** ρ (rho) step: rotates each 64-bit lane by a position-dependent offset. */
    private void rho() {
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                S[x][y] = Long.rotateLeft(S[x][y], rhoOffsets[x][y]);
            }
        }
    }

    /** π (pi) step: permutes lane coordinates within the 5×5 state. */
    private void pi() {
        long[][] B = new long[5][5];
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                B[y][(2 * x + 3 * y) % 5] = S[x][y];
            }
        }
        S = B;
    }

    /** χ (chi) step: non-linear mixing within each row. */
    private void chi() {
        for (int y = 0; y < 5; y++) {           // iterate rows (fixed y)
            long[] T = new long[5];
            for (int x = 0; x < 5; x++) T[x] = S[x][y];
            for (int x = 0; x < 5; x++) {
                S[x][y] ^= (~T[(x + 1) % 5]) & T[(x + 2) % 5];
            }
        }
    }

    /** ι (iota) step: injects the round constant into lane S[0][0]. */
    private void iota(int round) {
        S[0][0] ^= RC[round];
    }

    /**
     * Absorbs the padded message into the state in blocks of {@code rate} bits.
     * Bytes are XORed into lanes in little-endian order before each permutation.
     *
     * @param padded message already padded to a multiple of the rate in bytes
     */
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

    /**
     * Squeezes output bytes from the state until {@link #outputBits} have been produced.
     * If more bytes are needed than fit in the current state portion, the permutation is
     * applied again between output blocks (multi-rate sponge construction).
     *
     * @return the digest truncated to {@code outputBits/8} bytes
     */
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

    /**
     * Computes the SHA-3 digest of the given message.
     *
     * @param message input message bytes
     * @return digest as a byte array of length {@code outputBits/8}
     */
    public byte[] hash(byte[] message) {
        byte[] padded = pad(message);
        absorb(padded);
        return squeeze();
    }

    /**
     * Computes the SHA-3 digest and returns it as lowercase hexadecimal.
     *
     * @param message input message bytes
     * @return hex-encoded digest string (lowercase)
     */
    public String hexdigest(byte[] message) {
        byte[] digest = hash(message);
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    /**
     * Converts a hexadecimal string to a byte array.
     * <p>Whitespace is ignored. If the number of hex digits is odd, a leading
     * zero nibble is implicitly added. Invalid characters trigger an
     * {@link IllegalArgumentException} with the error index.</p>
     *
     * @param hex hex string (whitespace allowed); may be {@code null} or empty
     * @return byte array (empty if input is {@code null} or effectively empty)
     * @throws IllegalArgumentException if a non-hex character is encountered
     */
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

    /**
     * Command-line entry point.
     * <p>Reads an input file containing hexadecimal bytes (whitespace permitted),
     * converts it into the message byte array, computes the SHA3-224 digest, then
     * writes the lowercase hex digest to an output file and also prints it to stdout.</p>
     *
     * <p><strong>Usage:</strong> {@code java org.example.sha.SHA <inputHexFile> <outputDigestFile>}</p>
     *
     * @param args two arguments: input hex file and output digest file
     * @throws IOException if reading or writing files fails
     */
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
