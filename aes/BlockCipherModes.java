package aes;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

import static aes.Aes.*;


/**
 * Implements common block cipher modes of operation: ECB, CBC, OFB, and CTR.
 *
 * Usage:
 *   - Supply any BlockCipher implementation (e.g., AES) to these methods.
 *   - blockSize is in bytes (e.g., 16 for AES-128).
 */
public class BlockCipherModes {

    /**
     * Pads data with zero bytes up to a multiple of blockSize.
     */
    public static byte[] padZeros(byte[] data, int blockSize) {
        int padLen = (blockSize - (data.length % blockSize)) % blockSize;
        if (padLen == 0) {
            return data;
        }
        byte[] padded = new byte[data.length + padLen];
        System.arraycopy(data, 0, padded, 0, data.length);
        // rest are zeros by default
        return padded;
    }

    /**
     * Removes zero-byte padding. All trailing zero bytes are stripped.
     */
    public static byte[] unpadZeros(byte[] data) {
        int i = data.length - 1;
        while (i >= 0 && data[i] == 0) {
            i--;
        }
        return Arrays.copyOf(data, i + 1);
    }

    /**
     * Electronic Code Book (ECB) mode.
     */
    public static byte[] encryptECB(BlockCipher cipher, byte[] plaintext, int blockSize) {
        byte[] pt = padZeros(plaintext, blockSize);
        byte[] ct = new byte[pt.length];
        for (int i = 0; i < pt.length; i += blockSize) {
            byte[] block = Arrays.copyOfRange(pt, i, i + blockSize);
            byte[] enc = cipher.encryptBlock(block);
            System.arraycopy(enc, 0, ct, i, blockSize);
        }
        return ct;
    }

    public static byte[] decryptECB(BlockCipher cipher, byte[] ciphertext, int blockSize) {
        byte[] pt = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i += blockSize) {
            byte[] block = Arrays.copyOfRange(ciphertext, i, i + blockSize);
            byte[] dec = cipher.decryptBlock(block);
            System.arraycopy(dec, 0, pt, i, blockSize);
        }
        return unpadZeros(pt);
    }

    /**
     * Cipher Block Chaining (CBC) mode.
     */
    public static byte[] encryptCBC(BlockCipher cipher, byte[] plaintext, int blockSize, byte[] iv) {
        if (iv.length != blockSize) {
            throw new IllegalArgumentException("IV length must equal block size");
        }
        byte[] pt = padZeros(plaintext, blockSize);
        byte[] ct = new byte[pt.length];
        byte[] prev = Arrays.copyOf(iv, blockSize);

        for (int i = 0; i < pt.length; i += blockSize) {
            byte[] block = Arrays.copyOfRange(pt, i, i + blockSize);
            byte[] toEnc = xor(block, prev);
            byte[] enc = cipher.encryptBlock(toEnc);
            System.arraycopy(enc, 0, ct, i, blockSize);
            prev = enc;
        }
        return ct;
    }

    public static byte[] decryptCBC(BlockCipher cipher, byte[] ciphertext, int blockSize, byte[] iv) {
        if (iv.length != blockSize) {
            throw new IllegalArgumentException("IV length must equal block size");
        }
        byte[] pt = new byte[ciphertext.length];
        byte[] prev = Arrays.copyOf(iv, blockSize);

        for (int i = 0; i < ciphertext.length; i += blockSize) {
            byte[] cBlock = Arrays.copyOfRange(ciphertext, i, i + blockSize);
            byte[] dec = cipher.decryptBlock(cBlock);
            byte[] plainBlock = xor(dec, prev);
            System.arraycopy(plainBlock, 0, pt, i, blockSize);
            prev = cBlock;
        }
        return unpadZeros(pt);
    }

    /**
     * Output Feedback (OFB) mode.
     * Encryption and decryption are identical operations.
     */
    public static byte[] ofbKeystream(BlockCipher cipher, int length, int blockSize, byte[] iv) {
        if (iv.length != blockSize) {
            throw new IllegalArgumentException("IV length must equal block size");
        }
        byte[] keystream = new byte[length];
        byte[] state = Arrays.copyOf(iv, blockSize);
        int pos = 0;
        while (pos < length) {
            state = cipher.encryptBlock(state);
            int chunk = Math.min(blockSize, length - pos);
            System.arraycopy(state, 0, keystream, pos, chunk);
            pos += chunk;
        }
        return keystream;
    }

    public static byte[] encryptOFB(BlockCipher cipher, byte[] plaintext, int blockSize, byte[] iv) {
        byte[] keystream = ofbKeystream(cipher, plaintext.length, blockSize, iv);
        return xor(plaintext, keystream);
    }

    public static byte[] decryptOFB(BlockCipher cipher, byte[] ciphertext, int blockSize, byte[] iv) {
        // OFB decryption is identical to encryption
        return encryptOFB(cipher, ciphertext, blockSize, iv);
    }

    /**
     * Counter (CTR) mode.
     * Encryption and decryption are identical operations.
     */
    public static byte[] encryptCTR(BlockCipher cipher, byte[] plaintext, int blockSize, long initialCounter) {
        int length = plaintext.length;
        byte[] keystream = new byte[length];
        long counter = initialCounter;
        int pos = 0;

        while (pos < length) {
            byte[] counterBlock = longToBytes(counter++, blockSize);
            byte[] ksBlock = cipher.encryptBlock(counterBlock);
            int chunk = Math.min(blockSize, length - pos);
            System.arraycopy(ksBlock, 0, keystream, pos, chunk);
            pos += chunk;
        }
        return xor(plaintext, keystream);
    }

    public static byte[] decryptCTR(BlockCipher cipher, byte[] ciphertext, int blockSize, long initialCounter) {
        // CTR decryption is identical to encryption
        return encryptCTR(cipher, ciphertext, blockSize, initialCounter);
    }

    /**
     * Helper: XOR two byte arrays of the same length.
     */
    static byte[] xor(byte[] a, byte[] b) {
        int len = a.length;
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) (a[i] ^ b[i]);
        }
        return out;
    }

    /**
     * Converts a counter value to a big-endian byte array of given length.
     */
    private static byte[] longToBytes(long counter, int length) {
        byte[] out = new byte[length];
        for (int i = length - 1; i >= 0; i--) {
            out[i] = (byte) (counter & 0xFF);
            counter >>>= 8;
        }
        return out;
    }



}
