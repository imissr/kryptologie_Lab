package org.example.addativeChiffere;
import java.util.ArrayList;
import java.util.List;

public class Vigenere {

    /** Verschlüsselt Nur-Großbuchstaben-Text mit numerischem Key (0-25) */
    public String encrypt(String text, List<Integer> key) {
        StringBuilder sb = new StringBuilder();
        int counter = 0;
        for (char c : text.toCharArray()) {
            if (c >= 'A' && c <= 'Z') {
                int shift = key.get(counter % key.size());
                sb.append(shiftEnc(c, shift));
                counter++;
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** Entschlüsselt Nur-Großbuchstaben-Text mit numerischem Key (0-25) */
    public static String decrypt(String text, List<Integer> key) {
        StringBuilder sb = new StringBuilder();
        int counter = 0;
        for (char c : text.toCharArray()) {
            if (c >= 'A' && c <= 'Z') {
                int shift = key.get(counter % key.size());
                sb.append(shiftDec(c, shift));
                counter++;
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** Generiert numerischen Key (0-25) aus Passwort-String (A-Z) */
    public static List<Integer> generateKey(String password) {
        List<Integer> key = new ArrayList<>();
        for (char c : password.toUpperCase().toCharArray()) {
            if (c >= 'A' && c <= 'Z') key.add(c - 'A');
        }
        return key;
    }


    // --- Hilfsfunktionen ---
    private static char shiftEnc(char c, int k) {
        return (char) (((c - 'A' + k) % 26) + 'A');
    }
    private static char shiftDec(char c, int k) {
        return (char) (((c - 'A' - k + 26) % 26) + 'A');
    }


    // Index of Coincidence for a single string
    private static double IC(String s) {
        int n = s.length();
        if (n < 2) return 0.0;
        int[] counts = new int[26];
        for (char c : s.toCharArray()) {
            if ('A' <= c && c <= 'Z') counts[c - 'A']++;
        }
        double sum = 0;
        for (int freq : counts) {
            sum += (double) freq * (freq - 1);
        }
        return sum / (n * (n - 1));
    }

    // Average IC over keyLength interleaved substrings
    private static double getCoincidenceIndex(String s, int keyLength) {
        double total = 0;
        for (int i = 0; i < keyLength; i++) {
            StringBuilder sb = new StringBuilder();
            for (int j = i; j < s.length(); j += keyLength) {
                sb.append(s.charAt(j));
            }
            total += IC(sb.toString());
        }
        return total / keyLength;
    }

    // Estimate key length by finding the length 1..100 whose avg IC is within 80% of the max
    public static int getKeyLength(String s) {
        int maxKey = 100;
        double[] cis = new double[maxKey];
        double maxIC = 0;
        for (int L = 1; L <= maxKey; L++) {
            cis[L - 1] = getCoincidenceIndex(s, L);
            if (cis[L - 1] > maxIC) maxIC = cis[L - 1];
        }
        for (int L = 1; L <= maxKey; L++) {
            if (cis[L - 1] >= 0.8 * maxIC) {
                return L;
            }
        }
        return 1;
    }

    // Most frequent uppercase letter in the string
    public static char getMostCommonChar(String s) {
        int[] counts = new int[26];
        for (char c : s.toCharArray()) {
            if ('A' <= c && c <= 'Z') counts[c - 'A']++;
        }
        int maxIdx = 0;
        for (int i = 1; i < 26; i++) {
            if (counts[i] > counts[maxIdx]) {
                maxIdx = i;
            }
        }
        return (char) (maxIdx + 'A');
    }

    public static int[] getMostLikelyKey(String text) {
        String sanitized = text.replaceAll("[^A-Z]", "");
        int keyLength = getKeyLength(sanitized);
        int[] key = new int[keyLength];
        for (int i = 0; i < keyLength; i++) {
            StringBuilder sb = new StringBuilder();
            for (int j = i; j < sanitized.length(); j += keyLength) {
                sb.append(sanitized.charAt(j));
            }
            char mc = getMostCommonChar(sb.toString());
            key[i] = (mc - 'E' + 26) % 26;
        }
        return key;
    }

    public static String numberArrayToString(int[] key) {
        StringBuilder sb = new StringBuilder();
        for (int k : key) {
            sb.append((char) (k + 'A'));
        }
        return sb.toString();
    }

    // --- Command Line Interface Functions ---
    
    /**
     * Command line program for Vigenère encryption
     * Usage: java Vigenere encrypt [Inputfile] [Schlüssel] [Outputfile]
     */
    public static void encryptFromCommandLine(String[] args) {
        if (args.length != 4 || !args[0].equals("encrypt")) {
            System.err.println("Usage: java Vigenere encrypt [Inputfile] [Schlüssel] [Outputfile]");
            System.err.println("  Inputfile: Path to the input text file");
            System.err.println("  Schlüssel: Key string for encryption (A-Z)");
            System.err.println("  Outputfile: Path to the output file for encrypted text");
            return;
        }
        
        String inputFile = args[1];
        String keyString = args[2];
        String outputFile = args[3];
        
        try {
            // Read input text from file
            String plaintext = java.nio.file.Files.readString(java.nio.file.Paths.get(inputFile));
            
            // Validate and convert key
            if (!keyString.matches("[A-Za-z]+")) {
                System.err.println("Error: Key must contain only letters (A-Z)");
                return;
            }
            
            // Generate numeric key from password string
            List<Integer> key = generateKey(keyString);
            
            // Create Vigenère cipher instance and encrypt
            Vigenere vigenere = new Vigenere();
            String ciphertext = vigenere.encrypt(plaintext.toUpperCase(), key);
            
            // Write encrypted text to output file
            java.nio.file.Files.writeString(java.nio.file.Paths.get(outputFile), ciphertext);
            
            System.out.println("Encryption completed successfully!");
            System.out.println("Input file: " + inputFile);
            System.out.println("Key: " + keyString.toUpperCase());
            System.out.println("Output file: " + outputFile);
            
        } catch (java.io.IOException e) {
            System.err.println("File I/O error: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Error during encryption: " + e.getMessage());
        }
    }
    
    /**
     * Command line program for automatic Vigenère decryption
     * Usage: java Vigenere decrypt [Inputfile] [Outputfile]
     */
    public static void decryptFromCommandLine(String[] args) {
        if (args.length != 3 || !args[0].equals("decrypt")) {
            System.err.println("Usage: java Vigenere decrypt [Inputfile] [Outputfile]");
            System.err.println("  Inputfile: Path to the encrypted text file");
            System.err.println("  Outputfile: Path to the output file for decrypted text");
            System.err.println("Standard output: Found key");
            return;
        }
        
        String inputFile = args[1];
        String outputFile = args[2];
        
        try {
            // Read encrypted text from file
            String ciphertext = java.nio.file.Files.readString(java.nio.file.Paths.get(inputFile));
            
            // Automatically find the most likely key
            int[] keyArray = getMostLikelyKey(ciphertext);
            String foundKey = numberArrayToString(keyArray);
            
            // Convert key array to List<Integer> for decryption
            List<Integer> key = new ArrayList<>();
            for (int k : keyArray) {
                key.add(k);
            }
            
            // Decrypt the text
            String plaintext = decrypt(ciphertext, key);
            
            // Write decrypted text to output file
            java.nio.file.Files.writeString(java.nio.file.Paths.get(outputFile), plaintext);
            
            // Output the found key to standard output
            System.out.println(foundKey);
            
            System.err.println("Automatic decryption completed!");
            System.err.println("Input file: " + inputFile);
            System.err.println("Found key: " + foundKey);
            System.err.println("Output file: " + outputFile);
            
        } catch (java.io.IOException e) {
            System.err.println("File I/O error: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Error during decryption: " + e.getMessage());
        }
    }
    
    /**
     * Main method to handle command line arguments
     */
    public static void main(String[] args) {
        if (args.length == 0) {
            System.err.println("Vigenère Cipher Command Line Interface");
            System.err.println("Usage:");
            System.err.println("  java Vigenere encrypt [Inputfile] [Schlüssel] [Outputfile]");
            System.err.println("  java Vigenere decrypt [Inputfile] [Outputfile]");
            System.err.println();
            System.err.println("Commands:");
            System.err.println("  encrypt: Encrypt text with given key");
            System.err.println("  decrypt: Automatically decrypt text (key will be found and printed)");
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
