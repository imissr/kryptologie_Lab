import Addative_Chiffere.Caeser;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Scanner;

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
        selectAlgorithm(); // Step 1
        chooseAction();    // Step 2
    }

    public static void selectAlgorithm() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Please choose the encryption algorithm:");
        System.out.println("1. Caesar");
        System.out.print("Your choice (1-3): ");

        int choice = scanner.nextInt();
        scanner.nextLine(); // consume newline

        switch (choice) {
            case 1:
                selectedAlgorithm = "caesar";
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
        scanner.nextLine(); // consume newline

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

    public static void applyAction(String selectedAlgorithm, String action) {
        Scanner scanner = new Scanner(System.in);

        if (selectedAlgorithm.equals("caesar")) {
            Caeser caeser = new Caeser();

            switch (action) {
                case "encrypt":
                    System.out.print("Enter path to .txt file to encrypt: ");
                    String pathEncrypt = scanner.nextLine();
                    String plaintext = readPlainTextFromFile(pathEncrypt);
                    if (plaintext == null) return;

                    System.out.print("Enter shift: ");
                    int shiftEncrypt = scanner.nextInt();
                    scanner.nextLine(); // consume newline

                    String encrypted = caeser.encrypt(plaintext, shiftEncrypt);
                    System.out.println("Encrypted text:\n" + encrypted);

                    // Save automatically to file in project folder
                    writeTextToFile("encrypted_output.txt", encrypted);
                    break;

                case "decrypt":
                    System.out.print("Enter path to .txt file to decrypt: ");
                    String pathDecrypt = scanner.nextLine();
                    String encryptedText = readPlainTextFromFile(pathDecrypt);
                    if (encryptedText == null) return;

                    System.out.print("Enter shift: ");
                    int shiftDecrypt = scanner.nextInt();
                    scanner.nextLine(); // consume newline

                    String decrypted = caeser.decrypt(encryptedText, shiftDecrypt);
                    System.out.println("Decrypted text:\n" + decrypted);

                    // Save automatically to file in project folder
                    writeTextToFile("decrypted_output.txt", decrypted);
                    break;


                case "attack":
                    System.out.print("Enter encrypted text to brute-force: ");
                    String toAttack = scanner.nextLine();
                    System.out.println("Trying all possible Caesar shifts:");
                    for (int i = 1; i < 26; i++) {
                        // Wenn du eine decrypt-Methode hast:
                        // String attempt = caeser.decrypt(toAttack, i);
                        // System.out.println("Shift " + i + ": " + attempt);
                    }
                    break;
            }
        } else {
            System.out.println("The selected algorithm is not yet implemented.");
        }
    }


}
