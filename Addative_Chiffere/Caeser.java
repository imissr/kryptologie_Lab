package Addative_Chiffere;

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

    public static void analyzeFrequency(String text) {
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
    }
    public static int guessCaesarKey(String cipherText) {
        final String ENGLISH_ALPHABET = "abcdefghijklmnopqrstuvwxyz";
        Map<Character, Integer> freqMap = new HashMap<>();

        // Initialize frequency map for a-z
        for (char c : ENGLISH_ALPHABET.toCharArray()) {
            freqMap.put(c, 0);
        }

        // Count frequency of English letters only
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

        // Calculate shift assuming 'e' is the most frequent in plain text
        int cipherIndex = ENGLISH_ALPHABET.indexOf(mostFrequentChar);
        int eIndex = ENGLISH_ALPHABET.indexOf('e');
        int key = (cipherIndex - eIndex + ENGLISH_ALPHABET.length()) % ENGLISH_ALPHABET.length();

        System.out.println("Most frequent letter: " + mostFrequentChar);
        System.out.println("Estimated Caesar key (based on 'e'): " + key);
        return key;
    }



}
