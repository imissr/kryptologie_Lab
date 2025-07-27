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

}
