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
 *   - For ECB/CBC the CLI "-b" flag is treated as a chunk size (must be >= cipher block size, e.g., 16).
 *     Internally AES still operates on fixed 16-byte blocks; plaintext is split into chunkSize segments,
 *     and each chunk is processed in 16-byte blocks with only the final partial block (if any) zero-padded.
 */
public class BlockCipherModes {

    /**
     * Pads data with zero bytes up to a multiple of blockSize.
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
     * Removes zero-byte padding. All trailing zero bytes are stripped.
     */
    public static byte[] unpadZeros(byte[] data) {
        int i = data.length - 1;
        while (i >= 0 && data[i] == 0) {
            i--;
        }
        return Arrays.copyOf(data, i + 1);
    }

    /**
     * Electronic Code Book (ECB) mode with chunked segmentation.
     * Splits plaintext into chunkSize segments; within each chunk, treats data in cipher block size (e.g., 16)
     * and pads only the final block of the entire message if it's partial.
     */
    public static byte[] encryptECB(BlockCipher cipher, byte[] plaintext, int chunkSize) {
        int blockSize = 16;// AES fixed block size (typically 16)
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
     * ECB decryption. The chunkSize parameter is ignored because ciphertext is already aligned to internal blocks.
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

    /**
     * Cipher Block Chaining (CBC) mode with chunked segmentation like ECB.
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

    /**
     * Output Feedback (OFB) mode.
     * Encryption and decryption are identical operations.
     */
    public static byte[] ofbKeystream(BlockCipher cipher, int length, int blockSize, byte[] iv) {
        if (iv.length != blockSize) {
            throw new IllegalArgumentException("IV length must equal block size");
        }
        byte[] keystream = new byte[length];
        byte[] state = Arrays.copyOf(iv, blockSize);
        int pos = 0;
        while (pos < length) {
            state = cipher.encryptBlock(state);
            int chunk = Math.min(blockSize, length - pos);
            System.arraycopy(state, 0, keystream, pos, chunk);
            pos += chunk;
        }
        return keystream;
    }

    public static byte[] encryptOFB(BlockCipher cipher, byte[] plaintext, int blockSize, byte[] iv) {
        byte[] keystream = ofbKeystream(cipher, plaintext.length, blockSize, iv);
        return xor(plaintext, keystream);
    }

    public static byte[] decryptOFB(BlockCipher cipher, byte[] ciphertext, int blockSize, byte[] iv) {
        // OFB decryption is identical to encryption
        return encryptOFB(cipher, ciphertext, blockSize, iv);
    }

    /**
     * Counter (CTR) mode.
     * Encryption and decryption are identical operations.
     */
    public static byte[] encryptCTR(BlockCipher cipher, byte[] plaintext, int blockSize, long initialCounter) {
        int length = plaintext.length;
        byte[] keystream = new byte[length];
        long counter = initialCounter;
        int pos = 0;

        while (pos < length) {
            byte[] counterBlock = longToBytes(counter++, blockSize);
            byte[] ksBlock = cipher.encryptBlock(counterBlock);
            int chunk = Math.min(blockSize, length - pos);
            System.arraycopy(ksBlock, 0, keystream, pos, chunk);
            pos += chunk;
        }
        return xor(plaintext, keystream);
    }

    public static byte[] decryptCTR(BlockCipher cipher, byte[] ciphertext, int blockSize, long initialCounter) {
        // CTR decryption is identical to encryption
        return encryptCTR(cipher, ciphertext, blockSize, initialCounter);
    }

    /**
     * Helper: XOR two byte arrays of the same length.
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
     * Converts a counter value to a big-endian byte array of given length.
     */
    private static byte[] longToBytes(long counter, int length) {
        byte[] out = new byte[length];
        for (int i = length - 1; i >= 0; i--) {
            out[i] = (byte) (counter & 0xFF);
            counter >>>= 8;
        }
        return out;
    }

    /**
     * Reads a hex file and returns the bytes
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
     * Converts a byte array to hex string representation
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

    /**
     * Converts a byte array to long (big-endian)
     */
    private static long bytesToLong(byte[] bytes) {
        long result = 0;
        for (int i = 0; i < Math.min(8, bytes.length); i++) {
            result = (result << 8) | (bytes[i] & 0xFF);
        }
        return result;
    }

    /**
     * Simple argument parser for command line flags
     */
    private static class ArgumentParser {
        private final String[] args;

        public ArgumentParser(String[] args) {
            this.args = args;
        }

        public String getRequiredArgument(String flag) {
            for (int i = 0; i < args.length - 1; i++) {
                if (args[i].equals(flag)) {
                    return args[i + 1];
                }
            }
            throw new IllegalArgumentException("Required argument not found: " + flag);
        }

        public String getOptionalArgument(String flag, String defaultValue) {
            for (int i = 0; i < args.length - 1; i++) {
                if (args[i].equals(flag)) {
                    return args[i + 1];
                }
            }
            return defaultValue;
        }
    }

    /**
     * Command-line interface for AES encryption/decryption with different modes.
     *
     * Usage: java BlockCipherModes -m [mode] -o [operation] -i [inputFile] -k [keyFile] -out [outputFile] [-iv [ivFile]] [-s [sboxFile]] [-b [chunkSize]]
     *
     * Modes: ECB, CBC, OFB, CTR
     * Operations: encrypt, decrypt
     *
     * Note: For ECB/CBC, -b is a chunk size (must be >= cipher block size, e.g., 16). AES still uses its internal fixed block size.
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
                System.err.println("Error: Chunk/block size must be a positive reasonable value");
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
            System.out.println("Chunk/Block size parameter: " + chunkOrBlockSize + " bytes");

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void performAesOperation(String mode, String operation, String inputFile,
                                            String keyFile, String outputFile, String ivFile, String sboxFile, int chunkOrBlockSize)
            throws IOException {

        // Read input data - ALWAYS as hex for consistency with Main.java
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

            case "CBC":
                byte[] iv = readHexFile(ivFile);
                if (operation.equals("encrypt")) {
                    result = encryptCBC(cipher, inputData, chunkOrBlockSize, iv);
                } else {
                    result = decryptCBC(cipher, inputData, chunkOrBlockSize, iv);
                }
                break;

            case "OFB":
                byte[] ivOFB = readHexFile(ivFile);
                if (operation.equals("encrypt")) {
                    result = encryptOFB(cipher, inputData, chunkOrBlockSize, ivOFB);
                } else {
                    result = decryptOFB(cipher, inputData, chunkOrBlockSize, ivOFB);
                }
                break;

            case "CTR":
                // For CTR mode, use IV as counter (convert first 8 bytes to long)
                byte[] ivCTR = readHexFile(ivFile);
                long counter = bytesToLong(Arrays.copyOf(ivCTR, 8));
                if (operation.equals("encrypt")) {
                    result = encryptCTR(cipher, inputData, chunkOrBlockSize, counter);
                } else {
                    result = decryptCTR(cipher, inputData, chunkOrBlockSize, counter);
                }
                break;

            default:
                throw new IllegalArgumentException("Unsupported mode: " + mode);
        }

        // Write output
        writeOutput(result, outputFile, operation);
    }

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

    private static void printUsage() {
        System.out.println("AES Encryption/Decryption Tool - Block Cipher Modes");
        System.out.println("====================================================");
        System.out.println();
        System.out.println("Usage: java BlockCipherModes -m [mode] -o [operation] -i [inputFile] -k [keyFile] -out [outputFile] [-iv [ivFile]] [-s [sboxFile]] [-b [chunkSize]]");
        System.out.println();
        System.out.println("Required Parameters:");
        System.out.println("  -m   [mode]       : ECB, CBC, OFB, CTR");
        System.out.println("  -o   [operation]  : encrypt, decrypt");
        System.out.println("  -i   [inputFile]  : Path to input file (hex format expected)");
        System.out.println("  -k   [keyFile]    : Path to key file (hex format)");
        System.out.println("  -out [outputFile] : Path to output file");
        System.out.println();
        System.out.println("Optional Parameters:");
        System.out.println("  -iv  [ivFile]     : Path to IV file (hex format, required for CBC, OFB, CTR)");
        System.out.println("  -s   [sboxFile]   : Path to S-box file (defaults to SBox.txt)");
        System.out.println("  -b   [chunkSize]  : Chunk size in bytes for ECB/CBC segmentation (must be >= internal block size, default 16). AES still uses its fixed block size internally.");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  Encrypt with CBC using chunking:");
        System.out.println("    java BlockCipherModes -m CBC -o encrypt -i plaintext.txt -k key.txt -out encrypted.txt -iv iv.txt -b 31");
        System.out.println();
        System.out.println("  Decrypt with ECB:");
        System.out.println("    java BlockCipherModes -m ECB -o decrypt -i cipher.txt -k key.txt -out decrypted.txt -s sbox.txt -b 31");
        System.out.println();
        System.out.println("Note: For encryption, input file should contain hex values of plaintext.");
        System.out.println("      For decryption, input file should contain hex values of ciphertext.");
        System.out.println("      Output files will contain hex (for encryption) or plain text (for decryption).");
    }
}
