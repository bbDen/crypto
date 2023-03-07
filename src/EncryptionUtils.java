import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class EncryptionUtils {

    private static final String ALGORITHM = "AES";
    private static final int KEY_SIZE = 256;

    public static byte[] encrypt(String plaintext, String passphrase) throws Exception {
        byte[] keyBytes = generateKey(passphrase);
        SecretKeySpec key = new SecretKeySpec(keyBytes, ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext.getBytes("UTF-8"));
    }

    public static String decrypt(byte[] ciphertext, String passphrase) throws Exception {
        byte[] keyBytes = generateKey(passphrase);
        SecretKeySpec key = new SecretKeySpec(keyBytes, ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(ciphertext);
        return new String(decrypted, "UTF-8");
    }

    private static byte[] generateKey(String passphrase) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = sha.digest(passphrase.getBytes("UTF-8"));
        keyBytes = truncateKey(keyBytes, KEY_SIZE/8);
        return keyBytes;
    }

    private static byte[] truncateKey(byte[] keyBytes, int length) {
        byte[] truncated = new byte[length];
        System.arraycopy(keyBytes, 0, truncated, 0, length);
        return truncated;
    }

}