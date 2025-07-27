package rsa;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

/**
 * Einfache RSA-Verschlüsselung/Entschlüsselung in Java
 *
 * Verwendung:
 *   java RSA <input_file> <key_file> <output_destination>
 *
 * input_file:         Datei mit einer Dezimalzahl (Klartext oder Chiffre)
 * key_file:           Zwei Zeilen: Exponent (e oder d) und Modulus n, jeweils dezimal
 * output_destination: Pfad zu Zieldatei oder zu einem Verzeichnis.
 *                      Ist es ein Verzeichnis, wird die Ausgabedatei darin mit
 *                      demselben Namen wie die Eingabedatei angelegt.
 *
 * Die Potenzmodulberechnung erfolgt gemäß Pseudo-Code mit Quadrieren und Multiplizieren.
 */
public class RSA {
    public static BigInteger readBigInteger(String filePath) throws IOException {
        Path path = Paths.get(filePath);
        if (!Files.isRegularFile(path) || !Files.isReadable(path)) {
            throw new IOException("Datei nicht gefunden oder nicht lesbar: " + filePath);
        }
        String content = new String(Files.readAllBytes(path)).trim();
        return new BigInteger(content);
    }

    public static BigInteger modPow(BigInteger x, BigInteger m, BigInteger n) {
        BigInteger y = BigInteger.ONE;
        int r = m.bitLength() - 1;
        for (int i = 0; i <= r; i++) {
            if (m.testBit(i)) {
                y = y.multiply(x).mod(n);
            }
            x = x.multiply(x).mod(n);
        }
        return y;
    }

    public static BigInteger encrypt(BigInteger plaintext, BigInteger e, BigInteger n) {
        return modPow(plaintext, e, n);
    }

    public static BigInteger decrypt(BigInteger ciphertext, BigInteger d, BigInteger n) {
        return modPow(ciphertext, d, n);
    }

    public static void main(String[] args) {
        if (args.length != 3) {
            System.err.println("Usage: java RSA <input_file> <key_file> <output_destination>");
            System.exit(1);
        }

        String inputPath         = args[0];
        String keyPath           = args[1];
        String outputDestination = args[2];

        try {
            // Einlesen des Werts
            BigInteger value = readBigInteger(inputPath);
            List<String> keyLines = Files.readAllLines(Paths.get(keyPath));
            if (keyLines.size() < 2) {
                throw new IOException("Key file must contain two lines: exponent and modulus.");
            }
            BigInteger exponent = new BigInteger(keyLines.get(0).trim());
            BigInteger modulus  = new BigInteger(keyLines.get(1).trim());

            // Zielpfad bestimmen
            Path outDest = Paths.get(outputDestination);
            Path outFile;
            if (Files.exists(outDest) && Files.isDirectory(outDest)) {
                outFile = outDest.resolve(Paths.get(inputPath).getFileName());
            } else {
                outFile = outDest;
            }
            // Verzeichnisse anlegen
            if (outFile.getParent() != null && !Files.exists(outFile.getParent())) {
                Files.createDirectories(outFile.getParent());
            }

            // Berechnung
            BigInteger result = modPow(value, exponent, modulus);

            // Datei anlegen, falls nicht vorhanden, und beschreibbar machen
            if (!Files.exists(outFile)) {
                Files.createFile(outFile);
            }

            // Schreiben in die Datei
            try (var writer = Files.newBufferedWriter(outFile)) {
                writer.write(result.toString());
            }

            System.out.println("Operation completed. Result written to " + outFile);
        } catch (IOException e) {
            System.err.println("I/O error: " + e.getMessage());
            System.exit(1);
        } catch (NumberFormatException e) {
            System.err.println("Invalid number format: " + e.getMessage());
            System.exit(1);
        }
    }
}
