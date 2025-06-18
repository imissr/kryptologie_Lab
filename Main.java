

import Addative_Chiffere.Caeser;
import Addative_Chiffere.Vigenere;
import aes.Aes;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import java.util.stream.Collectors;

import static Addative_Chiffere.Vigenere.numberArrayToString;
import static aes.Aes.encryptBlock;
import static aes.Aes.readHexFile;


public class Main {

    public static String readPlainTextFromFile(String path) {
        try {
            return Files.readString(Paths.get(path));
        } catch (IOException e) {
            System.out.println("Error reading file: " + e.getMessage());
            return null;
        }
    }

    public static List<String> readKeyFromFile(String path) {
        try {
            return Files.readAllLines(Paths.get(path));
        } catch (IOException e) {
            System.out.println("Error reading key file: " + e.getMessage());
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

    public static void main(String[] args) throws IOException {
        selectAlgorithm();
        chooseAction();
    }

    public static void selectAlgorithm() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Please choose the encryption algorithm:");
        System.out.println("1. Caesar");
        System.out.println("2. Vigenere");
        System.out.println("3. AES");
        System.out.print("Your choice (1-3): ");

        int choice = scanner.nextInt();
        scanner.nextLine();

        switch (choice) {
            case 1:
                selectedAlgorithm = "caesar";
                break;
            case 2:
                selectedAlgorithm = "vigenere";
                break;
            case 3:
                selectedAlgorithm = "aes";
                break;
            default:
                System.out.println("Invalid number. Exiting...");
                System.exit(0);
        }
        System.out.println("You selected: " + selectedAlgorithm);
    }

    public static void chooseAction() throws IOException {
        Scanner scanner = new Scanner(System.in);
        System.out.println("What do you want to do with " + selectedAlgorithm + "?");
        System.out.println("1. Encrypt");
        System.out.println("2. Decrypt");
        if ("caesar".equals(selectedAlgorithm) || "vigenere".equals(selectedAlgorithm)) {
            System.out.println("3. Attack");
        }
        System.out.print("Your choice (1-" + ("aes".equals(selectedAlgorithm) ? 2 : 3) + "): ");

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
                if ("aes".equals(selectedAlgorithm)) {
                    System.out.println("Invalid action. Exiting...");
                    return;
                }
                action = "attack";
                break;
            default:
                System.out.println("Invalid action. Exiting...");
                return;
        }

        applyAction(selectedAlgorithm, action);
    }

    public static void applyAction(String algorithm, String action) throws IOException {
        Scanner scanner = new Scanner(System.in);
        switch (algorithm) {
            case "caesar":
                handleCaesar(action, scanner);
                break;
            case "vigenere":
                handleVigenere(action, scanner);
                break;
            case "aes":
                handleAes(action, scanner);
                break;
            default:
                System.out.println("Unknown algorithm. Exiting...");
        }
    }

    private static void handleCaesar(String action, Scanner scanner) {
        Caeser caeser = new Caeser();
        switch (action) {
            case "encrypt":
                System.out.print("Enter path to .txt file to encrypt: ");
                String pathEnc = scanner.nextLine();
                String plaintext = readPlainTextFromFile(pathEnc);
                if (plaintext == null) return;
                System.out.print("Enter shift: ");
                int shiftEnc = scanner.nextInt(); scanner.nextLine();
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
                int shiftDec = scanner.nextInt(); scanner.nextLine();
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
                System.out.println("\nDecrypted text (guessed key = " + guessedKey + "): ");
                System.out.println(guessedPlain);
                writeTextToFile("guessed_decryption.txt", guessedPlain);
                break;
        }
    }

    private static void handleVigenere(String action, Scanner scanner) {
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
                if (ct == null || ct.isEmpty()) { System.out.println("Error: Could not read cipher text or file is empty."); return; }
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

    private static void handleAes(String action, Scanner scanner) throws IOException {
        switch (action) {
            case "encrypt":
                System.out.print("Enter path to hex plaintext file: ");
                String ptHexPath = scanner.nextLine();
                String fileContent = Files.readString(Paths.get(ptHexPath), StandardCharsets.UTF_8);
                if (fileContent == null) return;
                // remove whitespace and parse
                byte[] plaintext = parseHexString(fileContent);

                System.out.print("Enter path to AES round‐keys file: ");
                String keyPathEnc = scanner.nextLine();
                System.out.print("Enter path to AES S‐Box: ");
                String sBoxLoc = scanner.nextLine();

                List<String> roundKeysEnc = readKeyFromFile(keyPathEnc);
                if (roundKeysEnc == null) return;

                byte[] ciphertext = encryptBlock(plaintext, sBoxLoc, keyPathEnc);

                StringBuilder sb = new StringBuilder();
                for (byte b : ciphertext) {
                    sb.append(String.format("%02x ", b));
                }

                System.out.println("Encrypted (hex):\n" + sb);
                writeTextToFile("aes_encrypted_output.txt", sb.toString());
                break;

            case "decrypt":
                // …
                break;

            default:
                System.out.println("Invalid action for AES.");
        }
    }

    // new helper to turn a raw hex string into bytes
    public static byte[] parseHexString(String hex) {
        String[] tokens = hex.trim().split("\\s+");
        byte[] out = new byte[tokens.length];
        for (int i = 0; i < tokens.length; i++) {
            out[i] = (byte) Integer.parseInt(tokens[i], 16);
        }
        return out;
    }
}
