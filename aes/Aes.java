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

    private static final byte[][] matrixDecrypt = new byte[][] {
            { (byte) 0x0E, (byte) 0x0B, (byte) 0x0D, (byte) 0x09 },
            { (byte) 0x09, (byte) 0x0E, (byte) 0x0B, (byte) 0x0D },
            { (byte) 0x0D, (byte) 0x09, (byte) 0x0E, (byte) 0x0B },
            { (byte) 0x0B, (byte) 0x0D, (byte) 0x09, (byte) 0x0E }
    };

    private static final byte[][] sBox = new byte[16][16];
    private static final byte[][] sBoxInv = new byte[16][16];
    private static final byte[][] roundKeys = new byte[11][16];

    public static void initSBoxes(String fileName) throws IOException {
        // 1) Read forward S-box from hex file into sBox
        readSBox(fileName, sBox);

    }
    public static void initInverseSBoxes( String fileName) throws IOException {
        // 2) Compute inverse S-box from sBox
        readSBox(fileName, sBoxInv);
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

    public static void invSubBytes(byte[][] state) {
        if (state.length != 4 || state[0].length != 4) {
            throw new IllegalArgumentException("state must be 4×4");
        }
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int row = (state[i][j] & 0xF0) >>> 4;
                int col = state[i][j] & 0x0F;
                state[i][j] = sBoxInv[row][col];
            }
        }
    }

    public static void invMixColumns(byte[][] state) {
        if (state.length != 4 || state[0].length != 4) {
            throw new IllegalArgumentException("state must be 4×4");
        }
        byte[][] temp = new byte[4][4];

        // For each column:
        for (int col = 0; col < 4; col++) {
            // For each row of the output column:
            for (int row = 0; row < 4; row++) {
                temp[row][col] = (byte) (
                        galoisMultiply(state[0][col], matrixDecrypt[row][0]) ^
                                galoisMultiply(state[1][col], matrixDecrypt[row][1]) ^
                                galoisMultiply(state[2][col], matrixDecrypt[row][2]) ^
                                galoisMultiply(state[3][col], matrixDecrypt[row][3])
                );
            }
        }

        // Copy the transformed columns back into state
        for (int i = 0; i < 4; i++) {
            System.arraycopy(temp[i], 0, state[i], 0, 4);
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

    public static void invShiftRows(byte[][] state) {
        if (state.length != 4 || state[0].length != 4) {
            throw new IllegalArgumentException("state must be 4×4");
        }

        // temp will hold our right-rotated rows
        byte[][] temp = new byte[4][4];

        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                // pick from (c - r) mod 4 to rotate right by r
                int srcCol = (c - r + 4) % 4;
                temp[r][c] = state[r][srcCol];
            }
        }

        // copy each row back
        for (int r = 0; r < 4; r++) {
            System.arraycopy(temp[r], 0, state[r], 0, 4);
        }
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


    public static byte[] decryptBlock(byte[] in, String locSbox, String locKeyRounds) throws IOException {
        initInverseSBoxes(locSbox);
        initRoundKeys(locKeyRounds);

        if (in.length != 16) {
            throw new IllegalArgumentException("Ciphertext block must be 16 bytes");
        }

        // 1) load into state (column-major)
        byte[][] state = new byte[4][4];
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                state[row][col] = in[col * 4 + row];
            }
        }

        // 2) initial round key (last key)
        addRoundKey(state, getRoundKeyMatrix(10));

        // 3) rounds 9→1
        for (int round = 9; round >= 1; round--) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, getRoundKeyMatrix(round));
            invMixColumns(state);
        }

        // 4) final round (no mixColumns)
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, getRoundKeyMatrix(0));

        // 5) unload state back to byte[16]
        byte[] out = new byte[16];
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                out[col * 4 + row] = state[row][col];
            }
        }
        return out;
    }


    }


