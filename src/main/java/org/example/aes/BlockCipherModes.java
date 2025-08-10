package org.example.aes;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Implements common block cipher modes of operation: ECB, CBC, OFB, and CTR.
 *
 * Usage:
 *   - Supply any BlockCipher implementation (e.g., AES) to these methods.
 *
 * Semantics of -b:
 *   - ECB/CBC: "-b" is a message CHUNK SIZE (>= AES block size, i.e., 16). The message is split into chunks of size b;
 *              inside each chunk AES still runs on 16-byte blocks; only the very last partial AES block (of the entire message)
 *              is zero-padded.
 *   - OFB/CTR: "-b" is a SEGMENT SIZE for XOR (any positive value). Keystream is generated in 16-byte blocks (AES block size)
 *              but XOR is applied in segments of size b. No padding is used in stream modes.
 */
public class BlockCipherModes {

    // =========================
    // Padding helpers (ECB/CBC)
    // =========================

    /**
     * Pads data with zero bytes to make it a multiple of blockSize.
     * @param data the data to pad
     * @param blockSize the target block size
     * @return padded data
     */
    public static byte[] padZeros(byte[] data, int blockSize) {
        int padLen = (blockSize - (data.length % blockSize)) % blockSize;
        if (padLen == 0) {
            return data;
        }
        byte[] padded = new byte[data.length + padLen];
        System.arraycopy(data, 0, padded, 0, data.length);
        // rest are zeros by default
        return padded;
    }

    /**
     * Removes trailing zero-byte padding from data.
     * @param data the padded data
     * @return data with padding removed
     */
    public static byte[] unpadZeros(byte[] data) {
        int i = data.length - 1;
        while (i >= 0 && data[i] == 0) {
            i--;
        }
        return Arrays.copyOf(data, i + 1);
    }

    // =========
    //   ECB
    // =========

    /**
     * Encrypts data using ECB mode with chunked processing.
     * @param cipher the block cipher to use
     * @param plaintext the data to encrypt
     * @param chunkSize the chunk size for processing (>= 16)
     * @return encrypted data
     */
    public static byte[] encryptECB(BlockCipher cipher, byte[] plaintext, int chunkSize) {
        int blockSize = 16; // AES fixed block size
        if (blockSize <= 0) {
            throw new IllegalArgumentException("Invalid cipher block size: " + blockSize);
        }
        if (chunkSize < blockSize) {
            throw new IllegalArgumentException("Chunk size must be >= cipher block size");
        }

        int totalLen = plaintext.length;
        ByteArrayOutputStream ctStream = new ByteArrayOutputStream();
        byte[] block = new byte[blockSize];

        for (int chunkStart = 0; chunkStart < totalLen; chunkStart += chunkSize) {
            int chunkLen = Math.min(chunkSize, totalLen - chunkStart);
            boolean isLastChunk = (chunkStart + chunkLen) == totalLen;

            for (int offsetInChunk = 0; offsetInChunk < chunkLen; offsetInChunk += blockSize) {
                int globalOffset = chunkStart + offsetInChunk;
                int remainingInChunk = chunkLen - offsetInChunk;

                if (remainingInChunk >= blockSize) {
                    // full block
                    System.arraycopy(plaintext, globalOffset, block, 0, blockSize);
                } else {
                    // partial AES block: only allowed if this is the very last block of entire message
                    if (!isLastChunk) {
                        throw new IllegalStateException("Unexpected partial AES block in non-final chunk");
                    }
                    Arrays.fill(block, (byte) 0); // zero padding
                    System.arraycopy(plaintext, globalOffset, block, 0, remainingInChunk);
                }

                byte[] enc = cipher.encryptBlock(block);
                ctStream.write(enc, 0, blockSize);
            }
        }

        return ctStream.toByteArray();
    }

    /**
     * Decrypts data using ECB mode.
     * @param cipher the block cipher to use
     * @param ciphertext the encrypted data
     * @param ignoredChunkSize chunk size parameter (ignored)
     * @return decrypted data with padding removed
     */
    public static byte[] decryptECB(BlockCipher cipher, byte[] ciphertext, int ignoredChunkSize) {
        int blockSize = 16;
        if (blockSize <= 0) {
            throw new IllegalArgumentException("Invalid cipher block size: " + blockSize);
        }
        if (ciphertext.length % blockSize != 0) {
            throw new IllegalArgumentException("Ciphertext length must be a multiple of block size");
        }
        byte[] pt = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i += blockSize) {
            byte[] block = Arrays.copyOfRange(ciphertext, i, i + blockSize);
            byte[] dec = cipher.decryptBlock(block);
            System.arraycopy(dec, 0, pt, i, blockSize);
        }
        return unpadZeros(pt);
    }

    // =========
    //   CBC
    // =========

    /**
     * Encrypts data using CBC mode with chunked processing.
     * @param cipher the block cipher to use
     * @param plaintext the data to encrypt
     * @param chunkSize the chunk size for processing (>= 16)
     * @param iv the initialization vector (16 bytes)
     * @return encrypted data
     */
    public static byte[] encryptCBC(BlockCipher cipher, byte[] plaintext, int chunkSize, byte[] iv) {
        int blockSize = 16;
        if (blockSize <= 0) {
            throw new IllegalArgumentException("Invalid cipher block size: " + blockSize);
        }
        if (iv.length != blockSize) {
            throw new IllegalArgumentException("IV length must equal cipher block size");
        }
        if (chunkSize < blockSize) {
            throw new IllegalArgumentException("Chunk size must be >= cipher block size");
        }

        int totalLen = plaintext.length;
        ByteArrayOutputStream ctStream = new ByteArrayOutputStream();
        byte[] block = new byte[blockSize];
        byte[] prev = Arrays.copyOf(iv, blockSize);

        for (int chunkStart = 0; chunkStart < totalLen; chunkStart += chunkSize) {
            int chunkLen = Math.min(chunkSize, totalLen - chunkStart);
            boolean isLastChunk = (chunkStart + chunkLen) == totalLen;

            for (int offsetInChunk = 0; offsetInChunk < chunkLen; offsetInChunk += blockSize) {
                int globalOffset = chunkStart + offsetInChunk;
                int remainingInChunk = chunkLen - offsetInChunk;

                if (remainingInChunk >= blockSize) {
                    System.arraycopy(plaintext, globalOffset, block, 0, blockSize);
                } else {
                    if (!isLastChunk) {
                        throw new IllegalStateException("Unexpected partial AES block in non-final chunk");
                    }
                    Arrays.fill(block, (byte) 0);
                    System.arraycopy(plaintext, globalOffset, block, 0, remainingInChunk);
                }

                byte[] toEnc = xor(block, prev);
                byte[] enc = cipher.encryptBlock(toEnc);
                ctStream.write(enc, 0, blockSize);
                prev = enc;
            }
        }

        return ctStream.toByteArray();
    }

    /**
     * Decrypts data using CBC mode.
     * @param cipher the block cipher to use
     * @param ciphertext the encrypted data
     * @param ignoredChunkSize chunk size parameter (ignored)
     * @param iv the initialization vector (16 bytes)
     * @return decrypted data with padding removed
     */
    public static byte[] decryptCBC(BlockCipher cipher, byte[] ciphertext, int ignoredChunkSize, byte[] iv) {
        int blockSize = 16;
        if (blockSize <= 0) {
            throw new IllegalArgumentException("Invalid cipher block size: " + blockSize);
        }
        if (iv.length != blockSize) {
            throw new IllegalArgumentException("IV length must equal cipher block size");
        }
        if (ciphertext.length % blockSize != 0) {
            throw new IllegalArgumentException("Ciphertext length must be a multiple of block size");
        }

        byte[] pt = new byte[ciphertext.length];
        byte[] prev = Arrays.copyOf(iv, blockSize);

        for (int i = 0; i < ciphertext.length; i += blockSize) {
            byte[] cBlock = Arrays.copyOfRange(ciphertext, i, i + blockSize);
            byte[] dec = cipher.decryptBlock(cBlock);
            byte[] plainBlock = xor(dec, prev);
            System.arraycopy(plainBlock, 0, pt, i, blockSize);
            prev = cBlock;
        }
        return unpadZeros(pt);
    }

    // =========
    //   OFB   (segment-size aware; no padding)
    // =========

    /**
     * Encrypts data using OFB mode with segment-sized XOR.
     * @param cipher the block cipher to use
     * @param plaintext the data to encrypt
     * @param segmentSize the XOR segment size (> 0)
     * @param iv the initialization vector (must be 16 bytes for AES)
     * @return encrypted data
     */
    public static byte[] encryptOFB(BlockCipher cipher, byte[] plaintext, int segmentSize, byte[] iv) {
        final int BS = 16;
        if (iv.length != BS) throw new IllegalArgumentException("IV length must be 16 bytes for AES/OFB");
        if (segmentSize <= 0) throw new IllegalArgumentException("Segment size must be > 0");

        byte[] out = new byte[plaintext.length];

        // OFB state: next keystream block = E_K(state); state = that keystream block
        byte[] state = Arrays.copyOf(iv, BS);
        byte[] ks = new byte[BS];
        int ksPos = BS; // force initial generation
        int pos = 0;

        while (pos < plaintext.length) {
            if (ksPos == BS) {
                state = cipher.encryptBlock(state);      // 16 in -> 16 out
                System.arraycopy(state, 0, ks, 0, BS);   // fill keystream buffer
                ksPos = 0;
            }
            int n = Math.min(segmentSize, Math.min(plaintext.length - pos, BS - ksPos));
            for (int i = 0; i < n; i++) {
                out[pos + i] = (byte) (plaintext[pos + i] ^ ks[ksPos + i]);
            }
            ksPos += n;
            pos += n;
        }
        return out;
    }

    /**
     * Decrypts data using OFB mode (identical to encryption).
     */
    public static byte[] decryptOFB(BlockCipher cipher, byte[] ciphertext, int segmentSize, byte[] iv) {
        return encryptOFB(cipher, ciphertext, segmentSize, iv);
    }

    // =========
    //   CTR   (segment-size aware; no padding)
    // =========

    /**
     * Encrypts data using CTR mode with segment-sized XOR.
     * IV must be 16 bytes; interpreted as (nonce || counter) where we increment the last 8 bytes (big-endian).
     * @param cipher the block cipher to use
     * @param data plaintext/ciphertext
     * @param segmentSize XOR segment size (> 0)
     * @param iv 16-byte IV (nonce||counter)
     * @return transformed data
     */
    public static byte[] encryptCTR(BlockCipher cipher, byte[] data, int segmentSize, byte[] iv) {
        final int BS = 16;
        if (iv.length != BS) throw new IllegalArgumentException("IV length must be 16 bytes for AES/CTR");
        if (segmentSize <= 0) throw new IllegalArgumentException("Segment size must be > 0");

        byte[] out = new byte[data.length];

        // counterBlock starts as IV; we increment the last 8 bytes as a big-endian counter
        byte[] counterBlock = Arrays.copyOf(iv, BS);

        byte[] ks = new byte[BS];
        int ksPos = BS; // force initial generation
        int pos = 0;

        while (pos < data.length) {
            if (ksPos == BS) {
                byte[] ksBlock = cipher.encryptBlock(counterBlock);
                System.arraycopy(ksBlock, 0, ks, 0, BS);
                ksPos = 0;
                incrementCounterBE(counterBlock, 8, 16); // increment 64-bit counter in bytes 8..15
            }
            int n = Math.min(segmentSize, Math.min(data.length - pos, BS - ksPos));
            for (int i = 0; i < n; i++) {
                out[pos + i] = (byte) (data[pos + i] ^ ks[ksPos + i]);
            }
            ksPos += n;
            pos += n;
        }
        return out;
    }

    /**
     * Decrypts data using CTR mode (identical to encryption).
     */
    public static byte[] decryptCTR(BlockCipher cipher, byte[] ciphertext, int segmentSize, byte[] iv) {
        return encryptCTR(cipher, ciphertext, segmentSize, iv);
    }

    // =========
    // Utilities
    // =========

    /**
     * XORs two byte arrays of the same length.
     * @param a first array
     * @param b second array
     * @return XOR result
     */
    static byte[] xor(byte[] a, byte[] b) {
        int len = a.length;
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) (a[i] ^ b[i]);
        }
        return out;
    }

    /**
     * Increments a big-endian counter in buf[off..end-1] by 1 (with carry).
     */
    private static void incrementCounterBE(byte[] buf, int off, int end) {
        for (int i = end - 1; i >= off; i--) {
            int v = (buf[i] & 0xFF) + 1;
            buf[i] = (byte) v;
            if (v <= 0xFF) break; // no carry -> done
        }
    }

    /**
     * Reads hex data from file and returns as byte array.
     * @param filePath path to hex file
     * @return byte array of hex data
     * @throws IOException if file reading fails
     */
    private static byte[] readHexFile(String filePath) throws IOException {
        String content = Files.readString(Paths.get(filePath), StandardCharsets.UTF_8).trim();
        String[] tokens = content.split("\\s+");

        byte[] bytes = new byte[tokens.length];
        for (int i = 0; i < tokens.length; i++) {
            bytes[i] = (byte) Integer.parseInt(tokens[i], 16);
        }
        return bytes;
    }

    /**
     * Converts byte array to hex string with spaces.
     * @param bytes the byte array to convert
     * @return hex string representation
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            result.append(String.format("%02X", bytes[i]));
            if (i < bytes.length - 1) {
                result.append(" ");
            }
        }
        return result.toString();
    }

    // =================
    //  CLI - argument parsing
    // =================

    /**
     * Simple argument parser for command line flags
     */
    private static class ArgumentParser {
        private final String[] args;

        /**
         * Constructor for argument parser.
         * @param args command line arguments
         */
        public ArgumentParser(String[] args) {
            this.args = args;
        }

        /**
         * Gets required command line argument by flag.
         * @param flag the flag to search for
         * @return the argument value
         * @throws IllegalArgumentException if flag not found
         */
        public String getRequiredArgument(String flag) {
            for (int i = 0; i < args.length - 1; i++) {
                if (args[i].equals(flag)) {
                    return args[i + 1];
                }
            }
            throw new IllegalArgumentException("Required argument not found: " + flag);
        }

        /**
         * Gets optional command line argument with default value.
         * @param flag the flag to search for
         * @param defaultValue value to return if flag not found
         * @return the argument value or default
         */
        public String getOptionalArgument(String flag, String defaultValue) {
            for (int i = 0; i < args.length - 1; i++) {
                if (args[i].equals(flag)) {
                    return args[i + 1];
                }
            }
            return defaultValue;
        }
    }

    // =================
    //  CLI - main
    // =================

    /**
     * Main method providing command-line interface for AES modes.
     * @param args command line arguments
     */
    public static void main(String[] args) {
        if (args.length < 8) {
            printUsage();
            System.exit(1);
        }

        try {
            // Parse command line arguments
            ArgumentParser parser = new ArgumentParser(args);

            String mode = parser.getRequiredArgument("-m").toUpperCase();
            String operation = parser.getRequiredArgument("-o").toLowerCase();
            String inputFile = parser.getRequiredArgument("-i");
            String keyFile = parser.getRequiredArgument("-k");
            String outputFile = parser.getRequiredArgument("-out");
            String ivFile = parser.getOptionalArgument("-iv", "");
            String sboxFile = parser.getOptionalArgument("-s", "src/main/java/org/example/aes/SBox.txt");
            int chunkOrBlockSize = Integer.parseInt(parser.getOptionalArgument("-b", "16"));

            // Validate arguments
            if (!Arrays.asList("ECB", "CBC", "OFB", "CTR").contains(mode)) {
                System.err.println("Error: Invalid mode. Supported modes: ECB, CBC, OFB, CTR");
                System.exit(1);
            }

            if (!Arrays.asList("encrypt", "decrypt").contains(operation)) {
                System.err.println("Error: Invalid operation. Supported operations: encrypt, decrypt");
                System.exit(1);
            }

            if (chunkOrBlockSize <= 0 || chunkOrBlockSize > 1024) {
                System.err.println("Error: Chunk/segment size must be a positive reasonable value");
                System.exit(1);
            }

            // Check if IV is needed for the mode
            boolean needsIV = !mode.equals("ECB");
            if (needsIV && (ivFile == null || ivFile.isEmpty())) {
                System.err.println("Error: IV file is required for " + mode + " mode. Use -iv parameter.");
                System.exit(1);
            }

            // Perform the operation
            performAesOperation(mode, operation, inputFile, keyFile, outputFile, ivFile, sboxFile, chunkOrBlockSize);

            System.out.println("Operation completed successfully!");
            System.out.println("Mode: " + mode);
            System.out.println("Operation: " + operation);
            System.out.println("Input: " + inputFile);
            System.out.println("Output: " + outputFile);
            System.out.println("Chunk/Segment size (-b): " + chunkOrBlockSize + " bytes");

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Performs the actual AES operation based on mode and parameters.
     * @param mode the cipher mode (ECB, CBC, OFB, CTR)
     * @param operation encrypt or decrypt
     * @param inputFile path to input file
     * @param keyFile path to key file
     * @param outputFile path to output file
     * @param ivFile path to IV file
     * @param sboxFile path to S-Box file
     * @param chunkOrBlockSize chunk size (ECB/CBC) or segment size (OFB/CTR)
     * @throws IOException if file operations fail
     */
    private static void performAesOperation(String mode, String operation, String inputFile,
                                            String keyFile, String outputFile, String ivFile, String sboxFile, int chunkOrBlockSize)
            throws IOException {

        // Read input data - ALWAYS as hex for consistency
        byte[] inputData = readHexFile(inputFile);

        // Create AES cipher
        AesCipher cipher = new AesCipher(sboxFile, keyFile);

        byte[] result;

        // Perform operation based on mode
        switch (mode) {
            case "ECB":
                if (operation.equals("encrypt")) {
                    result = encryptECB(cipher, inputData, chunkOrBlockSize);
                } else {
                    result = decryptECB(cipher, inputData, chunkOrBlockSize);
                }
                break;

            case "CBC": {
                byte[] iv = readHexFile(ivFile);
                if (operation.equals("encrypt")) {
                    result = encryptCBC(cipher, inputData, chunkOrBlockSize, iv);
                } else {
                    result = decryptCBC(cipher, inputData, chunkOrBlockSize, iv);
                }
                break;
            }

            case "OFB": {
                byte[] ivOFB = readHexFile(ivFile); // must be 16 bytes
                if (operation.equals("encrypt")) {
                    result = encryptOFB(cipher, inputData, chunkOrBlockSize, ivOFB);
                } else {
                    result = decryptOFB(cipher, inputData, chunkOrBlockSize, ivOFB);
                }
                break;
            }

            case "CTR": {
                byte[] ivCTR = readHexFile(ivFile); // 16 bytes: nonce||counter
                if (operation.equals("encrypt")) {
                    result = encryptCTR(cipher, inputData, chunkOrBlockSize, ivCTR);
                } else {
                    result = decryptCTR(cipher, inputData, chunkOrBlockSize, ivCTR);
                }
                break;
            }

            default:
                throw new IllegalArgumentException("Unsupported mode: " + mode);
        }

        // Write output
        writeOutput(result, outputFile, operation);
    }

    /**
     * Writes output data to file based on operation type.
     * @param data the data to write
     * @param outputFile path to output file
     * @param operation encrypt (hex output) or decrypt (text output)
     * @throws IOException if file writing fails
     */
    private static void writeOutput(byte[] data, String outputFile, String operation) throws IOException {
        if (operation.equals("encrypt")) {
            // Write encrypted data as hex
            String hexOutput = bytesToHex(data);
            Files.writeString(Paths.get(outputFile), hexOutput, StandardCharsets.UTF_8);
        } else {
            // Write decrypted data as text
            String textOutput = new String(data, StandardCharsets.UTF_8);
            Files.writeString(Paths.get(outputFile), textOutput, StandardCharsets.UTF_8);
        }
    }

    /**
     * Prints usage information for the command line interface.
     */
    private static void printUsage() {
        System.out.println("AES Encryption/Decryption Tool - Block Cipher Modes");
        System.out.println("====================================================");
        System.out.println();
        System.out.println("Usage: java BlockCipherModes -m [mode] -o [operation] -i [inputFile] -k [keyFile] -out [outputFile] [-iv [ivFile]] [-s [sboxFile]] [-b [size]]");
        System.out.println();
        System.out.println("Required Parameters:");
        System.out.println("  -m   [mode]       : ECB, CBC, OFB, CTR");
        System.out.println("  -o   [operation]  : encrypt, decrypt");
        System.out.println("  -i   [inputFile]  : Path to input file (hex format expected)");
        System.out.println("  -k   [keyFile]    : Path to key file (hex format)");
        System.out.println("  -out [outputFile] : Path to output file");
        System.out.println();
        System.out.println("Optional Parameters:");
        System.out.println("  -iv  [ivFile]     : Path to IV file (hex format; required for CBC, OFB, CTR; 16 bytes for AES)");
        System.out.println("  -s   [sboxFile]   : Path to S-box file (defaults to SBox.txt)");
        System.out.println("  -b   [size]       : ECB/CBC: chunk size (>=16). OFB/CTR: XOR segment size (>0).");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  Encrypt with CBC using chunking:");
        System.out.println("    java BlockCipherModes -m CBC -o encrypt -i plaintext.hex -k key.hex -out encrypted.hex -iv iv.hex -b 31");
        System.out.println();
        System.out.println("  Encrypt with OFB using 7-byte segments (stream mode):");
        System.out.println("    java BlockCipherModes -m OFB -o encrypt -i plaintext.hex -k key.hex -out encrypted.hex -iv iv.hex -b 7");
        System.out.println();
        System.out.println("Note: For encryption, input file should contain hex values of plaintext.");
        System.out.println("      For decryption, input file should contain hex values of ciphertext.");
        System.out.println("      Output files will contain hex (for encryption) or plain text (for decryption).");
    }
}
