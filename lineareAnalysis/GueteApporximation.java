package lineareAnalysis;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class GueteApporximation {
    
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
     * AND multiple binary strings of the same length
     */
    public static String andBin(String... args) {
        if (args.length == 0) return "";
        
        int length = args[0].length();
        StringBuilder result = new StringBuilder();
        
        for (int i = 0; i < length; i++) {
            int min = 1;
            for (String arg : args) {
                min = Math.min(min, Character.getNumericValue(arg.charAt(i)));
            }
            result.append(min);
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
     * Converts integer to 4 bit binary string
     */
    public static String intTo4BitBinary(int i) {
        return String.format("%04d", Integer.parseInt(Integer.toBinaryString(i)));
    }
    
    /**
     * Calculates the quality of the approximation
     */
    public static double calcQuality(List<String> U, List<String> V, List<String> approximation) {
        double T = 1.0;
        
        for (int i = 0; i < 4; i++) {
            int L = 0;
            for (int j = 0; j < 16; j++) {
                String u = U.get(j);
                String v = V.get(j);
                String Ua = andBin(u, approximation.get(i).substring(0, 4));
                String Vb = andBin(v, approximation.get(i).substring(4, 8));
                
                String xorResult = xor(
                    String.valueOf(Ua.charAt(0)),
                    String.valueOf(Ua.charAt(1)),
                    String.valueOf(Ua.charAt(2)),
                    String.valueOf(Ua.charAt(3)),
                    String.valueOf(Vb.charAt(0)),
                    String.valueOf(Vb.charAt(1)),
                    String.valueOf(Vb.charAt(2)),
                    String.valueOf(Vb.charAt(3))
                );
                
                if ("0".equals(xorResult)) {
                    L++;
                }
            }
            double bias = (L - 8.0) / 16.0;
            T *= Math.abs(bias);
        }
        
        return T;
    }
    
    /**
     * Perform quality approximation analysis
     */
    public static double performQualityAnalysis(String sBoxFile, String approximationFile, String outputFile) throws IOException {
        // Read S-Box file
        String sBoxContent = Files.readString(Paths.get(sBoxFile));
        
        // Create U array (0-15 in 4-bit binary)
        List<String> U = new ArrayList<>();
        for (int i = 0; i < 16; i++) {
            U.add(intTo4BitBinary(i));
        }
        
        // Create V array from S-Box
        List<String> V = new ArrayList<>();
        for (int i = 0; i < 16; i++) {
            if (i < sBoxContent.length()) {
                V.add(hexToBinary(String.valueOf(sBoxContent.charAt(i))));
            }
        }
        
        // Read approximation file
        String approximationContent = Files.readString(Paths.get(approximationFile));
        String[] lines = approximationContent.split("\\n");
        StringBuilder combined = new StringBuilder();
        for (String line : lines) {
            if (!line.trim().isEmpty()) {
                combined.append(line.trim()).append(" ");
            }
        }
        
        String[] approximationTokens = combined.toString().trim().split("\\s+");
        
        // Check for zero values at specific positions (1, 5, 9, 11)
        if (approximationTokens.length > 11) {
            if ("00".equals(approximationTokens[1]) || 
                "00".equals(approximationTokens[5]) || 
                "00".equals(approximationTokens[9]) || 
                "00".equals(approximationTokens[11])) {
                return -1.0;
            }
        }
        
        // Create approximation list
        List<String> approximation = new ArrayList<>();
        if (approximationTokens.length > 11) {
            approximation.add(hexToBinary(approximationTokens[1]));
            approximation.add(hexToBinary(approximationTokens[5]));
            approximation.add(hexToBinary(approximationTokens[9]));
            approximation.add(hexToBinary(approximationTokens[11]));
        }
        
        // Calculate quality
        double quality = calcQuality(U, V, approximation);
        
        // Write to output file if specified
        if (outputFile != null) {
            Files.writeString(Paths.get(outputFile), String.valueOf(quality));
        }
        
        return quality;
    }
    
    /**
     * Main method for command line usage
     */
    public static void main(String[] args) {
        try {
            if (args.length < 2 || args.length > 3) {
                System.out.println("Usage: java GueteApporximation sBox_file approximation_file [output_file]");
                System.exit(1);
            }
            
            String sBoxFile = args[0];
            String approximationFile = args[1];
            String outputFile = args.length == 3 ? args[2] : null;
            
            double quality = performQualityAnalysis(sBoxFile, approximationFile, outputFile);
            
            if (quality == -1.0) {
                System.out.println("-1");
                System.exit(0);
            }
            
            System.out.println(quality);
            
            if (outputFile != null) {
                System.out.println("Quality result written to: " + outputFile);
            }
            
        } catch (IOException e) {
            System.err.println("Error reading/writing files: " + e.getMessage());
            System.exit(1);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }
}
