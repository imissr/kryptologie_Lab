package aes;

import java.io.IOException;

public class AesCipher implements BlockCipher {

    private final String sBoxPath;
    private final String roundKeyPath;

    public AesCipher(String sBoxPath, String roundKeyPath) {
        this.sBoxPath = sBoxPath;
        this.roundKeyPath = roundKeyPath;
    }

    @Override
    public byte[] encryptBlock(byte[] plaintext) {
        try {
            return Aes.encryptBlock(plaintext, sBoxPath, roundKeyPath);
        } catch (IOException e) {
            throw new RuntimeException("Encryption failed: " + e.getMessage(), e);
        }
    }

    @Override
    public byte[] decryptBlock(byte[] ciphertext) {
        try {
            return Aes.decryptBlock(ciphertext, sBoxPath, roundKeyPath);
        } catch (IOException e) {
            throw new RuntimeException("Decryption failed: " + e.getMessage(), e);
        }
    }
}
