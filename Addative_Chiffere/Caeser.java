package Addative_Chiffere;

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
}
