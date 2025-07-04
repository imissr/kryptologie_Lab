package lineareAnalysis;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class Spn {
    
    // S-Box lookup table
    private static final String[] sbox = {
        "1110", "0100", "1101", "0001", "0010", "1111", "1011", "1000",
        "0011", "1010", "0110", "1100", "0101", "1001", "0000", "0111"
    };
    
    // Permutation table
    private static final int[] perm = {0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15};
    
    /**
     * Converts hex string to binary string
     */
    public static String hexToBinary(String hex) {
        // Remove non-hex characters
        hex = hex.replaceAll("[^a-f0-9]", "");
        StringBuilder binary = new StringBuilder();
        
        for (int i = 0; i < hex.length(); i += 2) {
            String hexByte = hex.substring(i, Math.min(i + 2, hex.length()));
            int value = Integer.parseInt(hexByte, 16);
            binary.append(String.format("%08d", Integer.parseInt(Integer.toBinaryString(value))));
        }
        
        return binary.toString();
    }
    
    /**
     * Converts binary string to hex string
     */
    public static String binaryToHex(String binary) {
        StringBuilder hex = new StringBuilder();
        
        for (int i = 0; i < binary.length(); i += 16) {
            StringBuilder block = new StringBuilder();
            for (int j = 0; j < 16; j += 4) {
                if (i + j + 4 <= binary.length()) {
                    String nibble = binary.substring(i + j, i + j + 4);
                    int value = Integer.parseInt(nibble, 2);
                    block.append(Integer.toHexString(value));
                }
            }
            if (hex.length() > 0) {
                hex.append(" ");
            }
            hex.append(block.toString());
        }
        
        return hex.toString();
    }
    
    /**
     * XOR two binary strings of the same length
     */
    public static String xor(String a, String b) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < a.length(); i++) {
            result.append(a.charAt(i) == b.charAt(i) ? '0' : '1');
        }
        return result.toString();
    }
    
    /**
     * Converts binary string to integer
     */
    public static int binaryToInt(String binary) {
        return Integer.parseInt(binary, 2);
    }
    
    /**
     * Converts binary string into 16 bit blocks
     */
    public static List<String> toBlocks(String binary) {
        List<String> blocks = new ArrayList<>();
        for (int i = 0; i < binary.length(); i += 16) {
            blocks.add(binary.substring(i, Math.min(i + 16, binary.length())));
        }
        return blocks;
    }
    
    /**
     * SBox substitution
     */
    public static String SBox(String x) {
        StringBuilder result = new StringBuilder();
        result.append(sbox[binaryToInt(x.substring(0, 4))]);
        result.append(sbox[binaryToInt(x.substring(4, 8))]);
        result.append(sbox[binaryToInt(x.substring(8, 12))]);
        result.append(sbox[binaryToInt(x.substring(12, 16))]);
        return result.toString();
    }
    
    /**
     * Permutation
     */
    public static String permute(String x) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            result.append(x.charAt(perm[i]));
        }
        return result.toString();
    }
    
    /**
     * SPN (Substitution-Permutation Network) encryption
     */
    public static String encrypt(String input, String k) {
        List<String> xBlocks = toBlocks(input);
        StringBuilder output = new StringBuilder();
        
        for (String x : xBlocks) {
            String w = x;
            
            // 3 rounds of substitution and permutation
            for (int r = 1; r <= 3; r++) {
                String u = xor(w, k);
                String v = SBox(u);
                w = permute(v);
            }
            
            // Final round without permutation
            String u = xor(w, k);
            String v = SBox(u);
            output.append(xor(v, k));
        }
        
        return output.toString();
    }
    
    /**
     * Main method
     */
    public static void main(String[] args) {
        if (args.length != 3) {
            System.out.println("Usage: java spn input_file key_file output_file");
            System.exit(1);
        }
        
        String inputFile = args[0];
        String keyFile = args[1];
        String outputFile = args[2];
        
        try {
            // Read input file and convert to binary
            String inputContent = Files.readString(Paths.get(inputFile));
            String input = hexToBinary(inputContent);
            
            // Read key file and convert to binary
            String keyContent = Files.readString(Paths.get(keyFile));
            String key = hexToBinary(keyContent);
            
            // Perform SPN encryption
            String output = encrypt(input, key);
            
            // Write output to file
            Files.writeString(Paths.get(outputFile), binaryToHex(output));
            
            System.out.println("SPN encryption completed successfully!");
            System.out.println("Output written to: " + outputFile);
            
        } catch (IOException e) {
            System.err.println("Error reading/writing files: " + e.getMessage());
            System.exit(1);
        }
    }
}
