package org.example.rsa;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

/**
 * Simple RSA encryption/decryption utility in Java using textbook (unpadded) RSA.
 *
 * <p><strong>Usage (CLI)</strong>:
 * <pre>{@code
 *   java org.example.rsa.RSA <operation> <input_file> <key_file> <output_destination>
 *
 *   operation:          "encrypt" or "decrypt"
 *   input_file:         File containing a single integer in decimal (plaintext or ciphertext)
 *   key_file:           Two lines in decimal: line 1 = exponent (e for encrypt, d for decrypt), line 2 = modulus n
 *   output_destination: Path to an output file or to a directory. If a directory is provided,
 *                       the output file will be created inside it with the same name as the input file.
 * }</pre>
 *
 * <p><strong>Input/Output format</strong>:
 * All values are read and written as base-10 (decimal) integers without any prefix. Leading/trailing whitespace
 * in files is trimmed.
 *
 * <p><strong>Algorithm</strong>:
 * Modular exponentiation is implemented via the classic square-and-multiply method, scanning the exponent
 * from least-significant bit to most-significant bit (LSB-first). For each set bit {@code i} in the exponent,
 * {@code y = (y * x) mod n}; after each step, {@code x = (x * x) mod n}.
 *
 * <p><strong>Security note</strong>:
 * This is <em>textbook RSA</em> without padding (e.g., no OAEP or PKCS#1 v1.5). Do not use as-is for
 * real-world cryptography. It is intended for educational purposes or assignments where the input numbers
 * already represent properly encoded blocks.
 *
 * @author Mohamad Kahled Minawe
 * @since 1.0
 */
public class RSA {

    /**
     * Reads a decimal integer from a file and returns it as a {@link BigInteger}.
     * The file is expected to contain a single integer in base 10. Leading and trailing
     * whitespace is ignored.
     *
     * @param filePath path to the file containing a decimal integer
     * @return the parsed {@code BigInteger}
     * @throws IOException if the path is not a readable regular file or if reading fails
     * @throws NumberFormatException if the file content is not a valid base-10 integer
     */
    public static BigInteger readBigInteger(String filePath) throws IOException {
        Path path = Paths.get(filePath);
        if (!Files.isRegularFile(path) || !Files.isReadable(path)) {
            throw new IOException("File not found or not readable: " + filePath);
        }
        String content = new String(Files.readAllBytes(path)).trim();
        return new BigInteger(content); // base-10 by default
    }

    /**
     * Computes {@code x^m mod n} using square-and-multiply (binary exponentiation).
     * This implementation scans the exponent bits from least-significant to most-significant (LSB-first).
     *
     * <p>For each bit {@code i} (starting at 0) up to {@code m.bitLength() - 1}:
     * <ul>
     *   <li>If {@code m.testBit(i)} is true, update {@code y = (y * x) mod n}.</li>
     *   <li>Then update {@code x = (x * x) mod n}.</li>
     * </ul>
     *
     * @param x base
     * @param m exponent (non-negative)
     * @param n modulus (positive)
     * @return {@code x^m mod n}
     * @throws ArithmeticException if {@code n} is zero
     */
    public static BigInteger modPow(BigInteger x, BigInteger m, BigInteger n) {
        BigInteger y = BigInteger.ONE;
        int r = m.bitLength() - 1;
        for (int i = 0; i <= r; i++) {
            if (m.testBit(i)) {
                y = y.multiply(x).mod(n);
            }
            x = x.multiply(x).mod(n);
        }
        return y;
    }

    /**
     * Encrypts a plaintext integer using RSA: {@code ciphertext = plaintext^e mod n}.
     *
     * <p>Note: No padding is applied. The caller must ensure {@code 0 <= plaintext < n}.
     *
     * @param plaintext plaintext as an integer in the range {@code [0, n)}
     * @param e public exponent
     * @param n modulus
     * @return ciphertext {@code = plaintext^e mod n}
     * @throws ArithmeticException if {@code n} is zero
     */
    public static BigInteger encrypt(BigInteger plaintext, BigInteger e, BigInteger n) {
        return modPow(plaintext, e, n);
    }

    /**
     * Decrypts a ciphertext integer using RSA: {@code plaintext = ciphertext^d mod n}.
     *
     * <p>Note: No padding is removed. The caller must ensure {@code 0 <= ciphertext < n}.
     *
     * @param ciphertext ciphertext as an integer in the range {@code [0, n)}
     * @param d private exponent
     * @param n modulus
     * @return plaintext {@code = ciphertext^d mod n}
     * @throws ArithmeticException if {@code n} is zero
     */
    public static BigInteger decrypt(BigInteger ciphertext, BigInteger d, BigInteger n) {
        return modPow(ciphertext, d, n);
    }

    /**
     * Command-line interface.
     *
     * <p><strong>Usage</strong>:
     * <pre>{@code
     *   java org.example.rsa.RSA <operation> <input_file> <key_file> <output_destination>
     * }</pre>
     *
     * <p><strong>Arguments</strong>:
     * <ul>
     *   <li>{@code operation}: {@code "encrypt"} or {@code "decrypt"}.</li>
     *   <li>{@code input_file}: Path to a file containing a single decimal integer (plaintext or ciphertext).</li>
     *   <li>{@code key_file}: Path to a file with two lines (both decimal):
     *     <ol>
     *       <li>Exponent (e for encryption or d for decryption)</li>
     *       <li>Modulus n</li>
     *     </ol>
     *   </li>
     *   <li>{@code output_destination}: Either a file path or a directory path. If a directory is given,
     *       the output file will be created there with the same filename as the input file.</li>
     * </ul>
     *
     * <p><strong>Behavior</strong>:
     * <ol>
     *   <li>Reads the input integer from {@code input_file}.</li>
     *   <li>Reads exponent and modulus (two lines) from {@code key_file}.</li>
     *   <li>Performs RSA encryption or decryption based on {@code operation}.</li>
     *   <li>Writes the result (decimal integer) to {@code output_destination}.</li>
     * </ol>
     *
     * @param args CLI arguments: {@code operation}, {@code input_file}, {@code key_file}, {@code output_destination}
     */
    public static void main(String[] args) {
        // Require exactly 4 arguments
        if (args.length != 4) {
            System.err.println("Usage: java org.example.rsa.RSA <operation> <input_file> <key_file> <output_destination>");
            System.err.println("  operation: encrypt or decrypt");
            System.exit(1);
        }

        String operation         = args[0].toLowerCase();
        String inputPath         = args[1];
        String keyPath           = args[2];
        String outputDestination = args[3];

        if (!operation.equals("encrypt") && !operation.equals("decrypt")) {
            System.err.println("Invalid operation. Use 'encrypt' or 'decrypt'");
            System.exit(1);
        }

        try {
            // Read input value
            BigInteger value = readBigInteger(inputPath);

            // Read key: first line = exponent, second line = modulus
            List<String> keyLines = Files.readAllLines(Paths.get(keyPath));
            if (keyLines.size() < 2) {
                throw new IOException("Key file must contain two lines: exponent and modulus.");
            }
            BigInteger exponent = new BigInteger(keyLines.get(0).trim());
            BigInteger modulus  = new BigInteger(keyLines.get(1).trim());

            // Resolve output path (file or directory)
            Path outDest = Paths.get(outputDestination);
            Path outFile;
            if (Files.exists(outDest) && Files.isDirectory(outDest)) {
                outFile = outDest.resolve(Paths.get(inputPath).getFileName());
            } else {
                outFile = outDest;
            }

            // Create parent directories if needed
            if (outFile.getParent() != null && !Files.exists(outFile.getParent())) {
                Files.createDirectories(outFile.getParent());
            }

            // Compute result
            BigInteger result;
            if (operation.equals("encrypt")) {
                result = encrypt(value, exponent, modulus);
                System.out.println("Encryption completed.");
            } else {
                result = decrypt(value, exponent, modulus);
                System.out.println("Decryption completed.");
            }

            // Ensure output file exists
            if (!Files.exists(outFile)) {
                Files.createFile(outFile);
            }

            // Write result (decimal) to file
            try (var writer = Files.newBufferedWriter(outFile)) {
                writer.write(result.toString());
            }

            System.out.println("Result written to " + outFile);
        } catch (IOException e) {
            System.err.println("I/O error: " + e.getMessage());
            System.exit(1);
        } catch (NumberFormatException e) {
            System.err.println("Invalid number format: " + e.getMessage());
            System.exit(1);
        }
    }
}
