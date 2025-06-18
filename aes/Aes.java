package aes;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

public class Aes {

    private static final byte[][] matrixEncrypt = new byte[][]{
            {(byte) 0x02, (byte) 0x03, (byte) 0x01, (byte) 0x01},
            {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x01},
            {(byte) 0x01, (byte) 0x01, (byte) 0x02, (byte) 0x03},
            {(byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0x02}
    };

    private static int[][] matrixDecrypt = {
            {14, 11, 13, 9},
            {9, 14, 11, 13},
            {13, 9, 14, 11},
            {11, 13, 9, 14}
    };

    private static final byte[][] sBox = new byte[16][16];
    private static final byte[][] sBoxInv = new byte[16][16];
    private static final byte[][] roundKeys = new byte[11][16];

    public static void initSBoxes(String fileName) throws IOException {
        // 1) Read forward S-box from hex file into sBox
        readSBox(fileName, sBox);
        // 2) Compute inverse mapping
        computeInverseSBox(sBox, sBoxInv);

    }

    public static void initRoundKeys(String fileName) throws IOException {
        // now: numRounds = 11, bytesPerRound = 16
        populateFromFile(fileName, roundKeys, 11, 16);
    }

    public static void populateFromFile(String fileName,
                                        byte[][] input,
                                        int numRounds,
                                        int bytesPerRound) throws IOException {
        List<String> lines = Files.readAllLines(Paths.get(fileName));
        if (lines.size() < numRounds) {
            throw new IOException("Expected at least " + numRounds +
                    " lines but found " + lines.size());
        }

        for (int round = 0; round < numRounds; round++) {
            String[] tokens = lines.get(round).trim().split("\\s+");
            if (tokens.length != bytesPerRound) {
                throw new IOException("Line " + round +
                        " has " + tokens.length + " bytes, expected " + bytesPerRound);
            }

            for (int b = 0; b < bytesPerRound; b++) {
                // store [byte-index][round]
                input[round][b] =
                        (byte) Integer.parseInt(tokens[b], 16);
            }
        }
    }

    public static void readSBox(String fileName, byte[][] input) throws IOException {
        List<String> lines = Files.readAllLines(Paths.get(fileName));
        for (int i = 0; i < 16; i++) {
            // remove *all* whitespace so you've got a 32‐char hex string
            String hex = lines.get(i).replaceAll("\\s+", "");
            if (hex.length() != 32) {
                throw new IOException("Invalid SBox line at row " + i + ": " + lines.get(i));
            }
            for (int j = 0; j < 16; j++) {
                input[i][j] = (byte) Integer.parseInt(hex.substring(j * 2, j * 2 + 2), 16);
            }
        }
    }

    public static void computeInverseSBox(byte[][] sBox, byte[][] sBoxInv) {
        for (int row = 0; row < 16; row++) {
            for (int col = 0; col < 16; col++) {
                int value = sBox[row][col] & 0xFF;
                int rowInv = (value >>> 4) & 0xF;
                int colInv = value & 0xF;
                sBoxInv[rowInv][colInv] = (byte) ((row << 4) | col);
            }
        }
    }

    public static void addRoundKey(byte[][] state, byte[][] roundKey) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] ^= roundKey[i][j];
            }
        }
    }

    public static void subBytes(byte[][] state) {
        if (state.length != 4 || state[0].length != 4) {
            throw new IllegalArgumentException("state must be 4×4");
        }
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int row = (state[i][j] & 0xF0) >>> 4;
                int col = state[i][j] & 0x0F;
                state[i][j] = sBox[row][col];
            }
        }
    }

    public static void shiftRows(byte[][] state) {
        if (state.length != 4 || state[0].length != 4) {
            throw new IllegalArgumentException("state must be 4×4");
        }
        byte[][] temp = new byte[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                temp[i][j] = state[i][(j + i) % 4];
            }
        }
        System.arraycopy(temp, 0, state, 0, state.length);
    }

    public static void mixColumns(byte[][] state) {
        if (state.length != 4 || state[0].length != 4) {
            throw new IllegalArgumentException("state must be 4×4");
        }
        byte[][] temp = new byte[4][4];

        // For each column:
        for (int col = 0; col < 4; col++) {
            // For each row of the output column:
            for (int row = 0; row < 4; row++) {
                temp[row][col] = (byte) (
                        galoisMultiply(state[0][col], matrixEncrypt[row][0]) ^
                                galoisMultiply(state[1][col], matrixEncrypt[row][1]) ^
                                galoisMultiply(state[2][col], matrixEncrypt[row][2]) ^
                                galoisMultiply(state[3][col], matrixEncrypt[row][3])
                );
            }
        }

        // Copy the transformed columns back into state
        for (int i = 0; i < 4; i++) {
            System.arraycopy(temp[i], 0, state[i], 0, 4);
        }
    }

    private static byte galoisMultiply(byte a, byte b) {
        int aa = a & 0xFF;
        int bb = b & 0xFF;
        int product = 0;

        for (int i = 0; i < 8; i++) {
            // If the lowest bit of bb is set, XOR in the current aa
            if ((bb & 1) != 0) {
                product ^= aa;
            }
            // Prepare aa for next bit: xtime(aa)
            boolean hiBitSet = (aa & 0x80) != 0;
            aa = (aa << 1) & 0xFF;
            if (hiBitSet) {
                // reduce by the AES polynomial x^8 + x^4 + x^3 + x + 1
                aa ^= 0x1B;
            }
            bb >>= 1;
        }

        return (byte) product;
    }

    public static byte[] readHexFile(String path) throws IOException {
        // Read entire file content as a UTF-8 string
        String content = Files.readString(Paths.get(path), StandardCharsets.UTF_8)
                .trim();

        // Split on any whitespace (spaces, tabs, newlines)
        String[] tokens = content.split("\\s+");

        // Parse each token into a byte
        byte[] bytes = new byte[tokens.length];
        for (int i = 0; i < tokens.length; i++) {
            int intValue = Integer.parseInt(tokens[i], 16);
            bytes[i] = (byte) (intValue & 0xFF);
        }

        return bytes;
    }

    private static byte[][] getRoundKeyMatrix(int round) {
        byte[][] k = new byte[4][4];
        byte[] flat = roundKeys[round];
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                k[row][col] = flat[col * 4 + row];
            }
        }
        return k;
    }

    public static byte[] encryptBlock(byte[] in , String locSbox , String locKeyRounds) throws IOException {
        initSBoxes( locSbox);
        initRoundKeys(locKeyRounds);

        if (in.length != 16) {
            throw new IllegalArgumentException("Plaintext block must be 16 bytes");
        }

        // 1) load into state (column-major)
        byte[][] state = new byte[4][4];
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                state[row][col] = in[col * 4 + row];
            }
        }

        // 2) initial round key
        addRoundKey(state, getRoundKeyMatrix(0));

        // 3) rounds 1–9
        for (int round = 1; round < 10; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, getRoundKeyMatrix(round));
        }

        // 4) final round (no mixColumns)
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, getRoundKeyMatrix(10));

        // 5) unload state back to byte[16]
        byte[] out = new byte[16];
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                out[col * 4 + row] = state[row][col];
            }
        }
        return out;
    }















   /* public static String hexToBinary(String hex) {
        hex = hex.replace(" ", "");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            String byteHex = hex.substring(i, i + 2);
            int val = Integer.parseInt(byteHex, 16);
            String bin = String.format("%8s", Integer.toBinaryString(val)).replace(' ', '0');
            sb.append(bin);
        }
        return sb.toString();
    }



    public static String binaryToHex(String binary) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < binary.length(); i += 8) {
            String byteBin = binary.substring(i, i + 8);
            int val = Integer.parseInt(byteBin, 2);
            String hexByte = String.format("%2s", Integer.toHexString(val)).replace(' ', '0');
            sb.append(hexByte);
            if (i + 8 < binary.length()) sb.append(" ");
        }
        return sb.toString();
    }

    public static String xor(String a, String b) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < a.length(); i++) {
            sb.append(a.charAt(i) == b.charAt(i) ? '0' : '1');
        }
        return sb.toString();
    }

    public static int[] byteToCoord(String b) {
        return new int[]{
                Integer.parseInt(b.substring(0, 4), 2),
                Integer.parseInt(b.substring(4, 8), 2)
        };
    }

    public static String addGalois(String a, String b) {
        return xor(a, b);
    }

    public static String doubleGalois(String a) {
        String t = a.substring(1) + "0";
        if (a.charAt(0) == '1') t = xor(t, "00011011");
        return t;
    }

    public static String mulGalois(String a, int b) {
        List<Integer> listLeft = new ArrayList<>();
        List<String> listRight = new ArrayList<>();
        int val = b;
        String aa = a;
        while (val > 1) {
            listLeft.add(val);
            listRight.add(aa);
            val /= 2;
            aa = doubleGalois(aa);
        }
        listLeft.add(val);
        listRight.add(aa);
        String sum = "00000000";
        for (int i = 0; i < listRight.size(); i++) {
            if (listLeft.get(i) % 2 != 0) sum = addGalois(sum, listRight.get(i));
        }
        return sum;
    }

    public static String[] matMulGalois(int[][] matrix, String[] col) {
        String[] mixed = new String[4];
        for (int i = 0; i < 4; i++) {
            String add0 = mulGalois(col[0], matrix[i][0]);
            String add1 = mulGalois(col[1], matrix[i][1]);
            String add2 = mulGalois(col[2], matrix[i][2]);
            String add3 = mulGalois(col[3], matrix[i][3]);
            mixed[i] = addGalois(add0, addGalois(add1, addGalois(add2, add3)));
        }
        return mixed;
    }

    public static String[][] addRoundKey(String[][] text, String[][] key) {
        String[][] result = new String[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                result[i][j] = xor(text[i][j], key[i][j]);
            }
        }
        return result;
    }

    public static String[][] subBytes(String[][] text) {
        String[][] result = new String[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int[] coord = byteToCoord(text[i][j]);
                result[i][j] = sBox[coord[0]][coord[1]];
            }
        }
        return result;
    }

    public static String[][] invSubBytes(String[][] text) {
        String[][] result = new String[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int[] coord = byteToCoord(text[i][j]);
                result[i][j] = sBoxInv[coord[0]][coord[1]];
            }
        }
        return result;
    }

    public static String[][] shiftRows(String[][] text) {
        String[][] shifted = new String[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                shifted[i][j] = text[(j + i) % 4][j];
            }
        }
        return shifted;
    }

    public static String[][] invShiftRows(String[][] text) {
        String[][] shifted = new String[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                shifted[i][j] = text[(i - j + 4) % 4][j];
            }
        }
        return shifted;
    }

    public static String[][] mixColumns(String[][] text) {
        String[][] mixed = new String[4][4];
        for (int i = 0; i < 4; i++) {
            mixed[i] = matMulGalois(matrixEncrypt, text[i]);
        }
        return mixed;
    }

    public static String[][] invMixColumns(String[][] text) {
        String[][] mixed = new String[4][4];
        for (int i = 0; i < 4; i++) {
            mixed[i] = matMulGalois(matrixDecrypt, text[i]);
        }
        return mixed;
    }

    public static String[][] convertToBlock(String text) {
        if (text.length() != 128) {
            throw new IllegalArgumentException(
                    "AES block must be exactly 128 bits; got "
                            + text.length() + " bits"
            );
        }
        String[][] block = new String[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int start = (i * 4 + j) * 8;
                block[i][j] = text.substring(start, start + 8);
            }
        }
        return block;
    }

    public static String blockToString(String[][] block) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                sb.append(block[i][j]);
            }
        }
        return sb.toString();
    }

    public static String encrypt(String text, List<String> key) {
        String[][] textBlock = convertToBlock(text);
        String[][][] keyBlock = new String[key.size()][4][4];
        for (int k = 0; k < key.size(); k++) {
            keyBlock[k] = convertToBlock(key.get(k));
        }
        textBlock = addRoundKey(textBlock, keyBlock[0]);
        for (int i = 1; i < 10; i++) {
            textBlock = subBytes(textBlock);
            textBlock = shiftRows(textBlock);
            textBlock = mixColumns(textBlock);
            textBlock = addRoundKey(textBlock, keyBlock[i]);
        }
        textBlock = subBytes(textBlock);
        textBlock = shiftRows(textBlock);
        textBlock = addRoundKey(textBlock, keyBlock[10]);
        return blockToString(textBlock);
    }

    public static String decrypt(String text, List<String> key) {
        String[][] textBlock = convertToBlock(text);
        String[][][] keyBlock = new String[key.size()][4][4];
        for (int k = 0; k < key.size(); k++) {
            keyBlock[k] = convertToBlock(key.get(k));
        }
        textBlock = addRoundKey(textBlock, keyBlock[10]);
        for (int i = 9; i > 0; i--) {
            textBlock = invSubBytes(textBlock);
            textBlock = invShiftRows(textBlock);
            textBlock = addRoundKey(textBlock, keyBlock[i]);
            textBlock = invMixColumns(textBlock);
        }
        textBlock = invSubBytes(textBlock);
        textBlock = invShiftRows(textBlock);
        textBlock = addRoundKey(textBlock, keyBlock[0]);
        return blockToString(textBlock);
    }

    static {
        try {
            Path dir = Paths.get(".").toAbsolutePath();
            List<String> sBoxLines = Files.readAllLines(dir.resolve("aes/SBox.txt"));
            for (int i = 0; i < sBoxLines.size(); i++) {
                String line = hexToBinary(sBoxLines.get(i).trim());
                for (int j = 0; j < 16; j++) {
                    sBox[i][j] = line.substring(j * 8, (j + 1) * 8);
                }
            }
            List<String> sBoxInvLines = Files.readAllLines(dir.resolve("aes/SBox.txt"));
            for (int i = 0; i < sBoxInvLines.size(); i++) {
                String line = hexToBinary(sBoxInvLines.get(i).trim());
                for (int j = 0; j < 16; j++) {
                    sBoxInv[i][j] = line.substring(j * 8, (j + 1) * 8);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }*/
    }


