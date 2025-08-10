package org.example.aes;

import org.example.aes.Aes;

import java.io.IOException;

/**
 * AES cipher implementation that implements the BlockCipher interface.
 * Provides wrapper methods for AES encryption/decryption with file-based configuration.
 */
public class AesCipher implements BlockCipher {

    private final String sBoxPath;
    private final String roundKeyPath;

    /**
     * Constructs an AES cipher with file paths for S-Box and round keys.
     * @param sBoxPath path to S-Box file
     * @param roundKeyPath path to round key file
     */
    public AesCipher(String sBoxPath, String roundKeyPath) {
        this.sBoxPath = sBoxPath;
        this.roundKeyPath = roundKeyPath;
    }

    /**
     * Encrypts a single block using AES algorithm.
     * @param plaintext the 16-byte block to encrypt
     * @return the encrypted 16-byte block
     */
    @Override
    public byte[] encryptBlock(byte[] plaintext) {
        try {
            return Aes.encryptBlock(plaintext, sBoxPath, roundKeyPath);
        } catch (IOException e) {
            throw new RuntimeException("Encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Decrypts a single block using AES algorithm.
     * @param ciphertext the 16-byte block to decrypt
     * @return the decrypted 16-byte block
     */
    @Override
    public byte[] decryptBlock(byte[] ciphertext) {
        try {
            return Aes.decryptBlock(ciphertext, sBoxPath, roundKeyPath);
        } catch (IOException e) {
            throw new RuntimeException("Decryption failed: " + e.getMessage(), e);
        }
    }

    // --- Command Line Interface Functions ---

    /**
     * Converts a byte array to hex string representation.
     * @param bytes the byte array to convert
     * @return hex string with spaces between bytes
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X ", b));
        }
        return result.toString().trim();
    }

    /**
     * Reads a hex file and returns the bytes.
     * @param filename path to the hex file
     * @return byte array from hex data
     * @throws IOException if file reading fails
     */
    private static byte[] readHexFile(String filename) throws IOException {
        return Aes.readHexFile(filename);
    }

    /**
     * Writes bytes to a hex file.
     * @param filename path to output file
     * @param data byte array to write as hex
     * @throws IOException if file writing fails
     */
    private static void writeHexFile(String filename, byte[] data) throws IOException {
        String hexString = bytesToHex(data);
        java.nio.file.Files.writeString(java.nio.file.Paths.get(filename), hexString);
    }

    /**
     * Command line interface for AES block encryption.
     * @param args [encrypt, inputFile, sboxFile, keyFile, outputFile]
     */
    public static void encryptFromCommandLine(String[] args) {
        if (args.length != 5 || !args[0].equals("encrypt")) {
            System.err.println("Usage: java AesCipher encrypt [Inputfile] [SBoxfile] [Keyfile] [Outputfile]");
            System.err.println("  Inputfile: Path to 128-bit plaintext in hex format");
            System.err.println("  SBoxfile: Path to S-Box file");
            System.err.println("  Keyfile: Path to 128-bit key file in hex format");
            System.err.println("  Outputfile: Path to output file for encrypted data");
            return;
        }

        String inputFile = args[1];
        String sboxFile = args[2];
        String keyFile = args[3];
        String outputFile = args[4];

        try {
            // Read input data (should be exactly 16 bytes / 128 bits)
            byte[] plaintext = readHexFile(inputFile);
            if (plaintext.length != 16) {
                System.err.println("Error: Input must be exactly 128 bits (16 bytes). Found: " + plaintext.length + " bytes");
                return;
            }

            // Create AES cipher instance
            AesCipher cipher = new AesCipher(sboxFile, keyFile);

            // Encrypt the block
            byte[] ciphertext = cipher.encryptBlock(plaintext);

            // Write encrypted data to output file
            writeHexFile(outputFile, ciphertext);

            System.out.println("AES Block Encryption completed successfully!");
            System.out.println("Input file: " + inputFile);
            System.out.println("S-Box file: " + sboxFile);
            System.out.println("Key file: " + keyFile);
            System.out.println("Output file: " + outputFile);
            System.out.println("Plaintext:  " + bytesToHex(plaintext));
            System.out.println("Ciphertext: " + bytesToHex(ciphertext));

        } catch (IOException e) {
            System.err.println("File I/O error: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Error during encryption: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Command line interface for AES block decryption.
     * @param args [decrypt, inputFile, sboxFile, keyFile, outputFile]
     */
    public static void decryptFromCommandLine(String[] args) {
        if (args.length != 5 || !args[0].equals("decrypt")) {
            System.err.println("Usage: java AesCipher decrypt [Inputfile] [SBoxfile] [Keyfile] [Outputfile]");
            System.err.println("  Inputfile: Path to 128-bit ciphertext in hex format");
            System.err.println("  SBoxfile: Path to S-Box file");
            System.err.println("  Keyfile: Path to 128-bit key file in hex format");
            System.err.println("  Outputfile: Path to output file for decrypted data");
            return;
        }

        String inputFile = args[1];
        String sboxFile = args[2];
        String keyFile = args[3];
        String outputFile = args[4];

        try {
            // Read input data (should be exactly 16 bytes / 128 bits)
            byte[] ciphertext = readHexFile(inputFile);
            if (ciphertext.length != 16) {
                System.err.println("Error: Input must be exactly 128 bits (16 bytes). Found: " + ciphertext.length + " bytes");
                return;
            }

            // Create AES cipher instance
            AesCipher cipher = new AesCipher(sboxFile, keyFile);

            // Decrypt the block
            byte[] plaintext = cipher.decryptBlock(ciphertext);

            // Write decrypted data to output file
            writeHexFile(outputFile, plaintext);

            System.out.println("AES Block Decryption completed successfully!");
            System.out.println("Input file: " + inputFile);
            System.out.println("S-Box file: " + sboxFile);
            System.out.println("Key file: " + keyFile);
            System.out.println("Output file: " + outputFile);
            System.out.println("Ciphertext: " + bytesToHex(ciphertext));
            System.out.println("Plaintext:  " + bytesToHex(plaintext));

        } catch (IOException e) {
            System.err.println("File I/O error: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Error during decryption: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Main method handling command line arguments for AES operations.
     * @param args command line arguments
     */
    public static void main(String[] args) {
        if (args.length == 0) {
            System.err.println("AES Block Cipher Command Line Interface");
            System.err.println("Usage:");
            System.err.println("  java AesCipher encrypt [Inputfile] [SBoxfile] [Keyfile] [Outputfile]");
            System.err.println("  java AesCipher decrypt [Inputfile] [SBoxfile] [Keyfile] [Outputfile]");
            System.err.println();
            System.err.println("Commands:");
            System.err.println("  encrypt: Encrypt a 128-bit block");
            System.err.println("  decrypt: Decrypt a 128-bit block");
            System.err.println();
            System.err.println("File Formats:");
            System.err.println("  - Input/Output: 128-bit data in hexadecimal format");
            System.err.println("  - Key: 128-bit key in hexadecimal format");
            System.err.println("  - SBox: S-Box lookup table");
            System.err.println("  - Whitespace and line breaks in hex files are ignored");
            return;
        }

        String command = args[0];
        switch (command) {
            case "encrypt":
                encryptFromCommandLine(args);
                break;
            case "decrypt":
                decryptFromCommandLine(args);
                break;
            default:
                System.err.println("Unknown command: " + command);
                System.err.println("Available commands: encrypt, decrypt");
        }
    }
}
