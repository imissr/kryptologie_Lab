package Addative_Chiffere;

import Addative_Chiffere.Caeser;
import Addative_Chiffere.Vigenere;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import java.util.stream.Collectors;

import static Addative_Chiffere.Vigenere.numberArrayToString;

public class Main {

    public static String readPlainTextFromFile(String path) {
        try {
            return Files.readString(Paths.get(path));
        } catch (IOException e) {
            System.out.println("Error reading file: " + e.getMessage());
            return null;
        }
    }

    public static void writeTextToFile(String fileName, String content) {
        try {
            Files.writeString(Paths.get(fileName), content);
            System.out.println("Output written to file: " + fileName);
        } catch (IOException e) {
            System.out.println("Error writing to file: " + e.getMessage());
        }
    }

    private static String selectedAlgorithm;

    public static void main(String[] args) {
        selectAlgorithm();
        chooseAction();
    }

    public static void selectAlgorithm() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Please choose the encryption algorithm:");
        System.out.println("1. Caesar");
        System.out.println("2. Vigenere");
        System.out.print("Your choice (1-2): ");

        int choice = scanner.nextInt();
        scanner.nextLine();

        switch (choice) {
            case 1:
                selectedAlgorithm = "caesar";
                break;
            case 2:
                selectedAlgorithm = "vigenere";
                break;
            default:
                System.out.println("Invalid number. Exiting...");
                System.exit(0);
        }
        System.out.println("You selected: " + selectedAlgorithm);
    }

    public static void chooseAction() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("What do you want to do with " + selectedAlgorithm + "?");
        System.out.println("1. Encrypt");
        System.out.println("2. Decrypt");
        System.out.println("3. Attack");
        System.out.print("Your choice (1-3): ");

        int actionChoice = scanner.nextInt();
        scanner.nextLine();

        String action;
        switch (actionChoice) {
            case 1:
                action = "encrypt";
                break;
            case 2:
                action = "decrypt";
                break;
            case 3:
                action = "attack";
                break;
            default:
                System.out.println("Invalid action. Exiting...");
                return;
        }

        applyAction(selectedAlgorithm, action);
    }

    public static void applyAction(String algorithm, String action) {
        Scanner scanner = new Scanner(System.in);

        if ("caesar".equals(algorithm)) {
            Caeser caeser = new Caeser();
            switch (action) {
                case "encrypt":
                    System.out.print("Enter path to .txt file to encrypt: ");
                    String pathEnc = scanner.nextLine();
                    String plaintext = readPlainTextFromFile(pathEnc);
                    if (plaintext == null) return;

                    System.out.print("Enter shift: ");
                    int shiftEnc = scanner.nextInt();
                    scanner.nextLine();

                    String encrypted = caeser.encrypt(plaintext, shiftEnc);
                    System.out.println("Encrypted text:\n" + encrypted);
                    writeTextToFile("encrypted_output.txt", encrypted);
                    break;

                case "decrypt":
                    System.out.print("Enter path to .txt file to decrypt: ");
                    String pathDec = scanner.nextLine();
                    String encryptedText = readPlainTextFromFile(pathDec);
                    if (encryptedText == null) return;

                    System.out.print("Enter shift: ");
                    int shiftDec = scanner.nextInt();
                    scanner.nextLine();

                    String decrypted = caeser.decrypt(encryptedText, shiftDec);
                    System.out.println("Decrypted text:\n" + decrypted);
                    writeTextToFile("decrypted_output.txt", decrypted);
                    break;

                case "attack":
                    System.out.print("Enter path to .txt file to analyze: ");
                    String pathAtk = scanner.nextLine();
                    String cipherText = readPlainTextFromFile(pathAtk);
                    if (cipherText == null) return;

                    caeser.analyzeFrequency(cipherText);
                    int guessedKey = caeser.guessCaesarKey(cipherText);
                    String guessedPlain = caeser.decrypt(cipherText, guessedKey);
                    System.out.println("\nDecrypted text (guessed key = " + guessedKey + "):");
                    System.out.println(guessedPlain);
                    writeTextToFile("guessed_decryption.txt", guessedPlain);
                    break;
            }
        }

        if ("vigenere".equals(algorithm)) {
            Vigenere vigenere = new Vigenere();
            switch (action) {
                case "encrypt":
                    System.out.print("Enter path to .txt file to encrypt: ");
                    String pathEncV = scanner.nextLine();
                    String plainV = readPlainTextFromFile(pathEncV);
                    if (plainV == null) return;

                    System.out.print("Enter key (letters only): ");
                    String keyStr = scanner.nextLine();
                    List<Integer> keyV = Vigenere.generateKey(keyStr);

                    String encV = vigenere.encrypt(plainV.toUpperCase(), keyV);
                    System.out.println("Encrypted text:\n" + encV);
                    writeTextToFile("encrypted_output_vigenere.txt", encV);
                    break;

                case "decrypt":
                    System.out.print("Enter path to .txt file to decrypt: ");
                    String pathDecV = scanner.nextLine();
                    String cipherV = readPlainTextFromFile(pathDecV);
                    if (cipherV == null) return;

                    System.out.print("Enter key (letters only): ");
                    String keyStrDec = scanner.nextLine();
                    List<Integer> keyVD = Vigenere.generateKey(keyStrDec);

                    String decV = vigenere.decrypt(cipherV.toUpperCase(), keyVD);
                    System.out.println("Decrypted text:\n" + decV);
                    writeTextToFile("decrypted_output_vigenere.txt", decV);
                    break;

                case "attack":
                    System.out.print("Enter path to .txt file to analyze: ");
                    String pathAtkV = scanner.nextLine();
                    String ct = readPlainTextFromFile(pathAtkV);
                    if (ct == null || ct.isEmpty()) {
                        System.out.println("Error: Could not read cipher text or file is empty.");
                        return;
                    }

                    int[] key = Vigenere.getMostLikelyKey(ct);
                   List<Integer> list = Arrays.stream(key).boxed().collect(Collectors.toList());

                    System.out.println("Estimated key length: " + key.length);
                    String plain = Vigenere.decrypt(ct, list);

                    String result = numberArrayToString(key) + System.lineSeparator() + plain;
                    System.out.println("Decrypted text with guessed key:\n" + result);
                    break;

                default:
                    System.out.println("Invalid action for Vigenere.");
            }
        }
    }
}
