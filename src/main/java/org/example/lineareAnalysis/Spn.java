package org.example.lineareAnalysis;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * SPN Verschlüsselungsprogramm
 * Usage: java -cp . org.example.lineareAnalysis.Spn <inputFile> <keyFile> <outputFile>
 */
public class Spn {
    private static final String[] SBOX = {
            "1110", "0100", "1101", "0001",
            "0010", "1111", "1011", "1000",
            "0011", "1010", "0110", "1100",
            "0101", "1001", "0000", "0111"
    };
    private static final int[] PERM = {0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15};

    public static String hexToBinary(String hex) {
        hex = hex.replaceAll("[^0-9A-Fa-f]", "");
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            String h = hex.substring(i, Math.min(i + 2, hex.length()));
            int v = Integer.parseInt(h, 16);
            b.append(String.format("%8s", Integer.toBinaryString(v)).replace(' ', '0'));
        }
        return b.toString();
    }

    public static String binaryToHex(String bin) {
        StringBuilder h = new StringBuilder();
        for (int i = 0; i < bin.length(); i += 4) {
            String nib = bin.substring(i, i + 4);
            h.append(Integer.toHexString(Integer.parseInt(nib, 2)).toUpperCase());
        }
        return h.toString();
    }

    public static List<String> toBlocks(String bin) {
        List<String> bs = new ArrayList<>();
        for (int i = 0; i < bin.length(); i += 16) {
            bs.add(bin.substring(i, Math.min(i + 16, bin.length())));
        }
        return bs;
    }

    public static String xor(String a, String b) {
        StringBuilder r = new StringBuilder();
        for (int i = 0; i < a.length(); i++) {
            r.append(a.charAt(i) == b.charAt(i) ? '0' : '1');
        }
        return r.toString();
    }

    public static String sbox(String blk) {
        StringBuilder o = new StringBuilder();
        for (int i = 0; i < 16; i += 4) {
            int idx = Integer.parseInt(blk.substring(i, i + 4), 2);
            o.append(SBOX[idx]);
        }
        return o.toString();
    }

    public static String permute(String blk) {
        StringBuilder o = new StringBuilder("                ");
        for (int i = 0; i < 16; i++) {
            o.setCharAt(i, blk.charAt(PERM[i]));
        }
        return o.toString();
    }

    public static String encrypt(String inputHex, String keyHex) {
        String bin = hexToBinary(inputHex);
        String kbin = hexToBinary(keyHex);
        List<String> bs = toBlocks(bin);
        StringBuilder cb = new StringBuilder();
        for (String blk : bs) {
            String state = blk;
            for (int r = 0; r < 3; r++) {
                state = xor(state, kbin);
                state = sbox(state);
                state = permute(state);
            }
            state = xor(state, kbin);
            state = sbox(state);
            state = xor(state, kbin);
            cb.append(state);
        }
        return binaryToHex(cb.toString());
    }


    public static void main(String[] args) {
        if (args.length != 3) {
            System.err.println("Usage: java org.example.lineareAnalysis.Spn <inputFile> <keyFile> <outputFile>");
            System.exit(1);
        }
        try {
            String hexInput = Files.readString(Paths.get(args[0]));
            String hexKey   = Files.readString(Paths.get(args[1]));
            String inputBin = hexToBinary(hexInput);
            String keyBin   = hexToBinary(hexKey);
            if (keyBin.length() != 16) {
                throw new IllegalArgumentException("Schlüssel muss genau 16 Bit haben.");
            }
            String outBin = encrypt(inputBin, keyBin);
            String hexOut = binaryToHex(outBin);
            Files.writeString(Paths.get(args[2]), hexOut);
            System.out.println("Verschlüsselung erfolgreich. Ausgabe: " + args[2]);
        } catch (IOException | IllegalArgumentException e) {
            System.err.println("Fehler: " + e.getMessage());
            System.exit(1);
        }
    }
}
