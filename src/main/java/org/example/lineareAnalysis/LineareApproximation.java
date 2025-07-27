package org.example.lineareAnalysis;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class LineareApproximation {
    
    // S-Box and related constants
    private static final String[] sbox = {
        "1110", "0100", "1101", "0001", "0010", "1111", "1011", "1000",
        "0011", "1010", "0110", "1100", "0101", "1001", "0000", "0111"
    };
    
    private static final String[] invSbox = new String[16];
    private static final int[] perm = {0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15};
    private static final String[] hexDigits = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"};
    private static final List<KeyPair> partialKeys = new ArrayList<>();
    
    // Initialize inverse S-box and partial keys
    static {
        // Initialize inverse S-box
        for (int i = 0; i < 16; i++) {
            String binaryI = intTo4BitBinary(i);
            for (int j = 0; j < 16; j++) {
                if (sbox[j].equals(binaryI)) {
                    invSbox[i] = intTo4BitBinary(j);
                    break;
                }
            }
        }
        
        // Initialize partial keys
        for (String i : hexDigits) {
            for (String j : hexDigits) {
                partialKeys.add(new KeyPair(hexToBinary(i), hexToBinary(j)));
            }
        }
    }
    
    // Helper class for key pairs
    static class KeyPair {
        String L1, L2;
        
        KeyPair(String L1, String L2) {
            this.L1 = L1;
            this.L2 = L2;
        }
    }
    
    // Helper class for plaintext-ciphertext pairs
    static class TextPair {
        String plaintext, ciphertext;
        
        TextPair(String plaintext, String ciphertext) {
            this.plaintext = plaintext;
            this.ciphertext = ciphertext;
        }
    }
    
    /**
     * Converts integer [0, 2^16-1] to hex string with 4 digits
     */
    public static String intTo4DigitHex(int i) {
        return String.format("%04x", i);
    }
    
    /**
     * Converts integer to 4 bit binary string
     */
    public static String intTo4BitBinary(int i) {
        return String.format("%04d", Integer.parseInt(Integer.toBinaryString(i)));
    }
    
    /**
     * XOR multiple binary strings of the same length
     */
    public static String xor(String... args) {
        if (args.length == 0) return "";
        
        int length = args[0].length();
        StringBuilder result = new StringBuilder();
        
        for (int i = 0; i < length; i++) {
            int sum = 0;
            for (String arg : args) {
                sum += Character.getNumericValue(arg.charAt(i));
            }
            result.append(sum % 2);
        }
        
        return result.toString();
    }
    
    /**
     * Converts hex string to binary string
     */
    public static String hexToBinary(String hex) {
        hex = hex.replaceAll("[^A-Fa-f0-9]", "");
        StringBuilder binary = new StringBuilder();
        
        for (int i = 0; i < hex.length(); i++) {
            int value = Integer.parseInt(String.valueOf(hex.charAt(i)), 16);
            binary.append(String.format("%04d", Integer.parseInt(Integer.toBinaryString(value))));
        }
        
        return binary.toString();
    }
    
    /**
     * Converts binary string to hex string
     */
    public static String binaryToHex(String binary) {
        StringBuilder hex = new StringBuilder();
        
        for (int i = 0; i < binary.length(); i += 4) {
            String nibble = binary.substring(i, Math.min(i + 4, binary.length()));
            int value = Integer.parseInt(nibble, 2);
            hex.append(Integer.toHexString(value));
        }
        
        return hex.toString();
    }
    
    /**
     * Converts binary string to integer
     */
    public static int binaryToInt(String binary) {
        return Integer.parseInt(binary, 2);
    }
    
    /**
     * Access InvSBox with binary string
     */
    public static String InvSBox(String x) {
        return invSbox[binaryToInt(x)];
    }
    
    /**
     * Calculate the most likely approximation
     */
    public static KeyPair getMaxKey(List<TextPair> M) {
        int[] alpha = new int[16 * 16];
        
        for (TextPair pair : M) {
            String x = pair.plaintext;
            String y = pair.ciphertext;
            
            for (KeyPair keyPair : partialKeys) {
                String L1 = keyPair.L1;
                String L2 = keyPair.L2;
                
                String v2 = xor(L1, y.substring(4, 8));
                String v4 = xor(L2, y.substring(12, 16));
                String u2 = InvSBox(v2);
                String u4 = InvSBox(v4);
                
                String xorResult = xor(
                    String.valueOf(x.charAt(4)),
                    String.valueOf(x.charAt(6)),
                    String.valueOf(x.charAt(7)),
                    String.valueOf(u2.charAt(1)),
                    String.valueOf(u2.charAt(3)),
                    String.valueOf(u4.charAt(1)),
                    String.valueOf(u4.charAt(3))
                );
                
                if ("0".equals(xorResult)) {
                    alpha[binaryToInt(L1) + binaryToInt(L2) * 16]++;
                }
            }
        }
        
        double maxval = -1;
        KeyPair maxkey = null;
        
        for (KeyPair keyPair : partialKeys) {
            String L1 = keyPair.L1;
            String L2 = keyPair.L2;
            double beta = Math.abs(alpha[binaryToInt(L1) + binaryToInt(L2) * 16] - M.size() / 2.0);
            
            if (beta > maxval) {
                maxval = beta;
                maxkey = keyPair;
            }
        }
        
        return maxkey;
    }
    
    /**
     * Generate random plaintexts
     */
    public static void generateExampleTexts(String plaintextFile, int numTexts) throws IOException {
        Random random = new Random();
        StringBuilder content = new StringBuilder();
        
        for (int i = 0; i < numTexts; i++) {
            int rand4digitHex = random.nextInt(65536); // 2^16
            content.append(intTo4DigitHex(rand4digitHex)).append("\n");
        }
        
        Files.writeString(Paths.get(plaintextFile), content.toString());
    }
    
    /**
     * Generate random plaintexts and their corresponding ciphertexts using SPN
     */
    public static void generatePlaintextCiphertextPairs(String plaintextFile, String ciphertextFile, String keyHex, int numTexts) throws IOException {
        Random random = new Random();
        StringBuilder plaintextContent = new StringBuilder();
        StringBuilder ciphertextContent = new StringBuilder();
        
        // Convert key to binary for SPN encryption
        String keyBinary = hexToBinary(keyHex);
        
        for (int i = 0; i < numTexts; i++) {
            // Generate random 4-digit hex plaintext
            int rand4digitHex = random.nextInt(65536); // 2^16
            String plaintextHex = intTo4DigitHex(rand4digitHex);
            
            // Convert to binary for SPN
            String plaintextBinary = hexToBinary(plaintextHex);
            
            // Encrypt using SPN
            String ciphertextBinary = Spn.encrypt(plaintextBinary, keyBinary);
            
            // Convert back to hex
            String ciphertextHex = binaryToHex(ciphertextBinary);
            
            // Add to content
            plaintextContent.append(plaintextHex).append("\n");
            ciphertextContent.append(ciphertextHex).append("\n");
        }
        
        // Write both files
        Files.writeString(Paths.get(plaintextFile), plaintextContent.toString());
        Files.writeString(Paths.get(ciphertextFile), ciphertextContent.toString());
    }

    /**
     * Perform linear approximation analysis
     */
    public static String performLinearApproximation(String plaintextFile, String ciphertextFile, String outputFile) throws IOException {
        // Read plaintexts
        String plaintextContent = Files.readString(Paths.get(plaintextFile));
        plaintextContent = plaintextContent.replaceAll("[^a-f0-9]", "");
        List<String> plaintexts = new ArrayList<>();
        for (int i = 0; i < plaintextContent.length(); i += 4) {
            if (i + 4 <= plaintextContent.length()) {
                plaintexts.add(hexToBinary(plaintextContent.substring(i, i + 4)));
            }
        }
        
        // Read ciphertexts
        String ciphertextContent = Files.readString(Paths.get(ciphertextFile));
        ciphertextContent = ciphertextContent.replaceAll("[^a-f0-9]", "");
        List<String> ciphertexts = new ArrayList<>();
        for (int i = 0; i < ciphertextContent.length(); i += 4) {
            if (i + 4 <= ciphertextContent.length()) {
                ciphertexts.add(hexToBinary(ciphertextContent.substring(i, i + 4)));
            }
        }
        
        // Create plaintext-ciphertext pairs
        List<TextPair> M = new ArrayList<>();
        for (int i = 0; i < Math.min(plaintexts.size(), ciphertexts.size()); i++) {
            M.add(new TextPair(plaintexts.get(i), ciphertexts.get(i)));
        }
        
        // Find the most likely key
        KeyPair maxKey = getMaxKey(M);
        String result = binaryToHex(maxKey.L1 + maxKey.L2);
        
        // Write to output file if specified
        if (outputFile != null) {
            Files.writeString(Paths.get(outputFile), result);
        }
        
        return result;
    }
    
    /**
     * Main method for command line usage
     */
    public static void main(String[] args) {
        try {
            if (args.length == 2) {
                // Generate example texts mode
                String plaintextFile = args[0];
                int numTexts = Integer.parseInt(args[1]);
                generateExampleTexts(plaintextFile, numTexts);
                System.out.println("Generated " + numTexts + " random plaintexts in " + plaintextFile);
            } else if (args.length == 2 || args.length == 3) {
                // Linear approximation mode
                String plaintextFile = args[0];
                String ciphertextFile = args[1];
                String outputFile = args.length == 3 ? args[2] : null;
                
                String result = performLinearApproximation(plaintextFile, ciphertextFile, outputFile);
                System.out.println(result);
            } else {
                System.out.println("Usage:");
                System.out.println("  Generate texts: java LineareApproximation plaintext_file number_of_texts");
                System.out.println("  Linear approx:  java LineareApproximation plaintexts.txt ciphertexts.txt [output_file]");
                System.exit(1);
            }
        } catch (IOException e) {
            System.err.println("Error reading/writing files: " + e.getMessage());
            System.exit(1);
        } catch (NumberFormatException e) {
            System.err.println("Invalid number format: " + e.getMessage());
            System.exit(1);
        }
    }
}
