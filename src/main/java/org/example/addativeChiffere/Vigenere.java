package org.example.addativeChiffere;
import java.util.ArrayList;
import java.util.List;

/**
 * Implementation of the Vigenère cipher encryption and decryption algorithm.
 * The Vigenère cipher is a polyalphabetic substitution cipher that uses a keyword
 * to shift letters by different amounts throughout the text.
 * 
 * This class provides methods for:
 * - Encrypting and decrypting text using a Vigenère cipher
 * - Key generation from password strings
 * - Automatic key length estimation using Index of Coincidence
 * - Automatic key recovery using frequency analysis
 * - Command-line interface for cipher operations
 * 
 * The implementation works with uppercase letters (A-Z) and preserves other characters.
 * 
 * @author Kryptologie Lab
 * @version 1.0
 */
public class Vigenere {

    /**
     * Encrypts uppercase text using the Vigenère cipher with a numeric key.
     * Only processes uppercase letters (A-Z), other characters are preserved unchanged.
     * 
     * @param text the plaintext to encrypt (should contain uppercase letters)
     * @param key the numeric key as a list of integers (0-25)
     * @return the encrypted text
     */
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

    /**
     * Decrypts uppercase text using the Vigenère cipher with a numeric key.
     * Only processes uppercase letters (A-Z), other characters are preserved unchanged.
     * 
     * @param text the ciphertext to decrypt (should contain uppercase letters)
     * @param key the numeric key as a list of integers (0-25) used for decryption
     * @return the decrypted plaintext
     */
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

    /**
     * Generates a numeric key (0-25) from a password string (A-Z).
     * Converts each letter in the password to its corresponding numeric value
     * where A=0, B=1, ..., Z=25.
     * 
     * @param password the password string containing letters (A-Z, case-insensitive)
     * @return a List of integers representing the numeric key (0-25 for each letter)
     */
    /** Generiert numerischen Key (0-25) aus Passwort-String (A-Z) */
    public static List<Integer> generateKey(String password) {
        List<Integer> key = new ArrayList<>();
        for (char c : password.toUpperCase().toCharArray()) {
            if (c >= 'A' && c <= 'Z') key.add(c - 'A');
        }
        return key;
    }


    /**
     * Shifts a character forward in the alphabet for encryption.
     * Handles wrapping around the alphabet (Z wraps to A).
     * 
     * @param c the character to shift (must be A-Z)
     * @param k the number of positions to shift forward (0-25)
     * @return the shifted character
     */
    // --- Hilfsfunktionen ---
    private static char shiftEnc(char c, int k) {
        return (char) (((c - 'A' + k) % 26) + 'A');
    }
    /**
     * Shifts a character backward in the alphabet for decryption.
     * Handles wrapping around the alphabet and avoids negative modulo results.
     * 
     * @param c the character to shift (must be A-Z)
     * @param k the number of positions to shift backward (0-25)
     * @return the shifted character
     */
    private static char shiftDec(char c, int k) {
        return (char) (((c - 'A' - k + 26) % 26) + 'A');
    }


    /**
     * Calculates the Index of Coincidence (IC) for a single string.
     * The IC is a measure of how similar the frequency distribution of letters
     * is to that of a natural language. Higher IC values suggest the text
     * resembles natural language more closely.
     * 
     * Formula: IC = Σ(fi * (fi - 1)) / (n * (n - 1))
     * where fi is the frequency of letter i, and n is the total length.
     * 
     * @param s the string to analyze (should contain uppercase letters A-Z)
     * @return the Index of Coincidence as a double value
     */
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

    /**
     * Calculates the average Index of Coincidence over keyLength interleaved substrings.
     * This method splits the text into subsequences based on the key length
     * and calculates the average IC across all subsequences.
     * 
     * For the correct key length, the average IC should be higher because
     * each subsequence would be encrypted with a single Caesar shift,
     * preserving the natural language frequency distribution.
     * 
     * @param s the text to analyze
     * @param keyLength the assumed key length for creating subsequences
     * @return the average Index of Coincidence across all subsequences
     */
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

    /**
     * Estimates the key length by finding the length that maximizes the Index of Coincidence.
     * Tests key lengths from 1 to 100 and returns the first length whose average IC
     * is within 80% of the maximum IC found.
     * 
     * This method works on the principle that the correct key length will result
     * in subsequences that more closely resemble natural language, thus having
     * a higher Index of Coincidence.
     * 
     * @param s the encrypted text to analyze
     * @return the estimated key length (1-100)
     */
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

    /**
     * Finds the most frequent uppercase letter in the given string.
     * Only counts letters A-Z and returns the letter that appears most frequently.
     * 
     * @param s the string to analyze
     * @return the most common uppercase letter (A-Z)
     */
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

    /**
     * Determines the most likely key for a Vigenère cipher using cryptanalysis.
     * 
     * The algorithm:
     * 1. Removes all non-alphabetic characters
     * 2. Estimates the key length using Index of Coincidence analysis
     * 3. For each position in the key, extracts the corresponding subsequence
     * 4. Finds the most common letter in each subsequence
     * 5. Assumes this letter corresponds to 'E' (most common in English/German)
     * 6. Calculates the shift needed to map the most common letter to 'E'
     * 
     * @param text the encrypted text to analyze
     * @return an array of integers representing the most likely key
     */
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

    /**
     * Converts a numeric key array to its corresponding string representation.
     * Each integer in the array (0-25) is converted to its corresponding letter (A-Z).
     * 
     * @param key the numeric key array where each element is 0-25
     * @return the string representation of the key (A-Z letters)
     */
    public static String numberArrayToString(int[] key) {
        StringBuilder sb = new StringBuilder();
        for (int k : key) {
            sb.append((char) (k + 'A'));
        }
        return sb.toString();
    }

    /**
     * Command line interface for Vigenère encryption.
     * 
     * Expected arguments: ["encrypt", inputFile, keyString, outputFile]
     * - inputFile: Path to the input text file
     * - keyString: Key string for encryption (A-Z letters)
     * - outputFile: Path to the output file for encrypted text
     * 
     * The method reads the input file, encrypts it using the provided key,
     * and writes the result to the output file.
     * 
     * @param args command line arguments as specified above
     */
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
     * Command line interface for automatic Vigenère decryption.
     * 
     * Expected arguments: ["decrypt", inputFile, outputFile]
     * - inputFile: Path to the encrypted text file
     * - outputFile: Path to the output file for decrypted text
     * 
     * The method automatically determines the most likely key using cryptanalysis,
     * decrypts the text, writes the result to the output file, and prints the
     * discovered key to standard output.
     * 
     * @param args command line arguments as specified above
     */
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
     * Main method to handle command line arguments for Vigenère cipher operations.
     * 
     * Supports two modes:
     * 1. Encryption: java Vigenere encrypt [Inputfile] [Key] [Outputfile]
     * 2. Automatic Decryption: java Vigenere decrypt [Inputfile] [Outputfile]
     * 
     * The program provides detailed usage information when called without arguments
     * or with invalid arguments.
     * 
     * @param args command line arguments specifying the operation and file paths
     */
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
