package org.example.addativeChiffere;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

public class Caeser {
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

    // -3 % 26 would return -3 ->avoid negative number
    public static char shiftDec(int charAscii, int key) {
        // Shift within uppercase letters (A-Z)
        int shifted = ((charAscii - 65 - key + 26) % 26) + 65;
        return (char) shifted;
    }

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


    // Read text from file
    public static String readFromFile(String filename) throws IOException {
        return new String(Files.readAllBytes(Paths.get(filename)));
    }

    // Write text to file
    public static void writeToFile(String filename, String content) throws IOException {
        Files.write(Paths.get(filename), content.getBytes());
    }

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
