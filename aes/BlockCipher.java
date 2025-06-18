package aes;

/**
 * Generic block cipher interface for single-block encryption/decryption.
 */
public interface BlockCipher {
    /**
     * Encrypt exactly one block of plaintext (blockSize bytes).
     */
    byte[] encryptBlock(byte[] block);

    /**
     * Decrypt exactly one block of ciphertext (blockSize bytes).
     */
    byte[] decryptBlock(byte[] block);
}