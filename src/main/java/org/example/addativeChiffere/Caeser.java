package org.example.addativeChiffere;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Implementation of the Caesar cipher encryption and decryption algorithm.
 * The Caesar cipher is a simple substitution cipher where each letter in the plaintext
 * is shifted a certain number of places down or up the alphabet.
 * 
 * This class provides methods for:
 * - Encrypting and decrypting text using a Caesar cipher
 * - Frequency analysis of text
 * - Automatic key guessing based on frequency analysis
 * - File I/O operations for cipher operations
 * 
 * @author Kryptologie Lab
 * @version 1.0
 */
public class Caeser {
    /**
     * Encrypts the given text using the Caesar cipher with the specified key.
     * Only uppercase letters (A-Z) are encrypted, other characters remain unchanged.
     * 
     * @param text the plaintext to encrypt (should contain uppercase letters)
     * @param key the shift value for encryption (0-25)
     * @return the encrypted text
     */
    public static String encrypt(String text, int key) {
        StringBuilder cryptText = new StringBuilder();

        for (int i = 0; i < text.length(); i++) {
            char currentChar = text.charAt(i);
            int charAscii = (int) currentChar;
            char cryptChar = currentChar;
            //ignore Ä,Ü
            if (charAscii >= 65 && charAscii <= 90) { // A-Z
                cryptChar = shiftEnc(charAscii, key);
            }

            cryptText.append(cryptChar);
        }

        return cryptText.toString();
    }

    /**
     * Shifts a character forward in the alphabet for encryption.
     * This method handles the wrapping around the alphabet (Z wraps to A).
     * 
     * Example: shiftEnc('X', 5) returns 'C'
     * Calculation: ((88 - 65 + 5) % 26) + 65 = ((23 + 5) % 26) + 65 = (2) + 65 = 67 → 'C'
     * 
     * @param charAscii the ASCII value of the character to shift (must be A-Z, 65-90)
     * @param key the number of positions to shift forward
     * @return the shifted character
     */
    /*charAscii = 88  // 'X'
    shifted = ((88 - 65 + 5) % 26) + 65
            = (28 % 26) + 65 28->x
            = 2 + 65
            = 67 → 'C'*/
    public static char shiftEnc(int charAscii, int key) {
        // Shift within uppercase letters (A-Z)
        // A in acii = 65
        int shifted = ((charAscii - 65 + key) % 26) + 65;
        return (char) shifted;
    }

    /**
     * Shifts a character backward in the alphabet for decryption.
     * This method handles the wrapping around the alphabet and avoids negative numbers.
     * The +26 ensures that negative modulo results are handled correctly.
     * 
     * Note: -3 % 26 would return -3, so we add 26 to avoid negative numbers
     * 
     * @param charAscii the ASCII value of the character to shift (must be A-Z, 65-90)
     * @param key the number of positions to shift backward
     * @return the shifted character
     */
    // -3 % 26 would return -3 ->avoid negative number
    public static char shiftDec(int charAscii, int key) {
        // Shift within uppercase letters (A-Z)
        int shifted = ((charAscii - 65 - key + 26) % 26) + 65;
        return (char) shifted;
    }

    /**
     * Decrypts the given cipher text using the Caesar cipher with the specified key.
     * Only uppercase letters (A-Z) are decrypted, other characters remain unchanged.
     * 
     * @param cipherText the encrypted text to decrypt
     * @param key the shift value used for decryption (0-25)
     * @return the decrypted plaintext
     */
    public String decrypt(String cipherText, int key) {



        StringBuilder cryptText = new StringBuilder();

        for (int i = 0; i < cipherText.length(); i++) {
            char currentChar = cipherText.charAt(i);
            int charAscii = (int) currentChar;
            char cryptChar = currentChar;

            if (charAscii >= 65 && charAscii <= 90) { // A-Z
                cryptChar = shiftDec(charAscii, key);
            }

            cryptText.append(cryptChar);
        }

        return cryptText.toString();
    }

    /**
     * Analyzes the frequency of letters in the given text and prints the results.
     * This method counts the occurrence of each letter (a-z) in the text and
     * calculates the percentage frequency of each letter.
     * 
     * @param text the text to analyze (case-insensitive)
     * @return a LinkedHashMap containing the frequency count for each letter (a-z)
     */
    public static Map<Character, Integer> analyzeFrequency(String text) {
        final String ENGLISH_ALPHABET = "abcdefghijklmnopqrstuvwxyz";
        Map<Character, Integer> freqMap = new LinkedHashMap<>();
        int totalLetters = 0;

        for (char c : ENGLISH_ALPHABET.toCharArray()) {
            freqMap.put(c, 0);
        }

        for (char c : text.toLowerCase().toCharArray()) {
            if (freqMap.containsKey(c)) {
                freqMap.put(c, freqMap.get(c) + 1);
                totalLetters++;
            }
        }

        System.out.println("\n Letter frequency (%):");
        for (char c : ENGLISH_ALPHABET.toCharArray()) {
            int count = freqMap.get(c);
            double percent = totalLetters > 0 ? (count * 100.0 / totalLetters) : 0;
            System.out.printf("%c: %5.2f%% (%d times)\n", c, percent, count);
        }
        return freqMap;
    }
    /**
     * Attempts to guess the Caesar cipher key by performing frequency analysis.
     * This method assumes that the most frequent letter in the cipher text
     * corresponds to 'e' (the most common letter in German text).
     * 
     * The algorithm:
     * 1. Counts the frequency of each letter in the cipher text
     * 2. Finds the most frequent letter
     * 3. Calculates the shift needed to map this letter to 'e'
     * 4. Returns this shift as the estimated key
     * 
     * @param cipherText the encrypted text to analyze (case-insensitive)
     * @return the estimated Caesar cipher key (0-25)
     */
    public static int guessCaesarKey(String cipherText) {
        final String GERMAN_ALPHABET = "abcdefghijklmnopqrstuvwxyz";
        Map<Character, Integer> freqMap = new HashMap<>();

        // Initialize frequency map for a-z
        for (char c : GERMAN_ALPHABET.toCharArray()) {
            freqMap.put(c, 0);
        }

        // Count frequency of German letters only
        for (char c : cipherText.toLowerCase().toCharArray()) {
            if (freqMap.containsKey(c)) {
                freqMap.put(c, freqMap.get(c) + 1);
            }
        }

        // Find most frequent character
        char mostFrequentChar = 'e'; // default fallback
        int maxCount = 0;
        for (Map.Entry<Character, Integer> entry : freqMap.entrySet()) {
            if (entry.getValue() > maxCount) {
                maxCount = entry.getValue();
                mostFrequentChar = entry.getKey();
            }
        }

        // For German text, 'e' is still the most common letter
        // Calculate shift assuming 'e' is the most frequent in plain text
        int cipherIndex = GERMAN_ALPHABET.indexOf(mostFrequentChar);
        int eIndex = GERMAN_ALPHABET.indexOf('e');
        int key = (cipherIndex - eIndex + GERMAN_ALPHABET.length()) % GERMAN_ALPHABET.length();

        System.out.println("Most frequent letter: " + mostFrequentChar);
        System.out.println("Estimated Caesar key (based on 'e'): " + key);
        return key;
    }


    /**
     * Reads text content from a specified file.
     * 
     * @param filename the path to the file to read
     * @return the content of the file as a String
     * @throws IOException if an I/O error occurs reading from the file
     */
    // Read text from file
    public static String readFromFile(String filename) throws IOException {
        return new String(Files.readAllBytes(Paths.get(filename)));
    }

    /**
     * Writes text content to a specified file.
     * If the file doesn't exist, it will be created. If it exists, it will be overwritten.
     * 
     * @param filename the path to the file to write
     * @param content the text content to write to the file
     * @throws IOException if an I/O error occurs writing to the file
     */
    // Write text to file
    public static void writeToFile(String filename, String content) throws IOException {
        Files.write(Paths.get(filename), content.getBytes());
    }

    /**
     * Main method providing command-line interface for Caesar cipher operations.
     * 
     * Usage modes:
     * 1. Encrypt/Decrypt with key: java Caeser <input.txt> <key> <output.txt>
     *    - Positive key for encryption, negative key for decryption
     * 2. Automatic decryption: java Caeser <input.txt> <output.txt>
     *    - Uses frequency analysis to guess the key automatically
     * 
     * The program handles file I/O, key validation, and error management.
     * Keys are automatically normalized to the range 0-25.
     * 
     * @param args command line arguments as described above
     */
    public static void main(String[] args) {
        try {
            if (args.length == 3) {
                // Mode: [input.txt] [key] [output.txt] - Encrypt/Decrypt with given key
                String inputFile = args[0];
                int key = Integer.parseInt(args[1]);
                String outputFile = args[2];
                key = ((key % 26) + 26) % 26;

                String inputText = readFromFile(inputFile);
                String result;

                // Determine if we should encrypt or decrypt based on key sign or content
                // For simplicity, we'll assume positive key = encrypt, negative = decrypt
                if (key >= 0) {
                    result = encrypt(inputText.toUpperCase(), key);
                    System.out.println("Encrypted with key: " + key);
                } else {
                    result = new Caeser().decrypt(inputText.toUpperCase(), Math.abs(key));
                    System.out.println("Decrypted with key: " + Math.abs(key));
                }

                writeToFile(outputFile, result);
                System.out.println("Result written to: " + outputFile);

            } else if (args.length == 2) {
                // Mode: [input.txt] [output.txt] - Automatic decryption using frequency analysis
                String inputFile = args[0];
                String outputFile = args[1];

                String cipherText = readFromFile(inputFile);
                
                // Analyze frequency and guess key
                int guessedKey = guessCaesarKey(cipherText);
                
                // Decrypt with guessed key
                String decryptedText = new Caeser().decrypt(cipherText.toUpperCase(), guessedKey);
                
                // Write decrypted text to output file
                writeToFile(outputFile, decryptedText);
                
                // Output key to standard output as required
                System.out.println(guessedKey);
                System.out.println("Automatic decryption completed. Key: " + guessedKey);
                System.out.println("Decrypted text written to: " + outputFile);

            } else {
                // Print usage information
                System.out.println("Usage:");
                System.out.println("  Encrypt/Decrypt with key: java Caeser <input.txt> <key> <output.txt>");
                System.out.println("    - Positive key for encryption, negative key for decryption");
                System.out.println("  Automatic decryption:     java Caeser <input.txt> <output.txt>");
                System.out.println("    - Uses frequency analysis to guess the key");
            }

        } catch (IOException e) {
            System.err.println("File error: " + e.getMessage());
            System.exit(1);
        } catch (NumberFormatException e) {
            System.err.println("Invalid key format. Please provide a number.");
            System.exit(1);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }


}
