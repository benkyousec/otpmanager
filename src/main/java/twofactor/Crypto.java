package twofactor;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Passphrase-based encryption for exported account lists.
 *
 * <p>Uses PBKDF2-HMAC-SHA256 for key derivation and AES-256-GCM for
 * authenticated encryption, both from the JDK, so no third-party crypto
 * dependency is required. GCM's authentication tag means a tampered file fails
 * to decrypt rather than silently importing modified secrets.</p>
 */
final class Crypto
{
    /** OWASP-recommended PBKDF2-HMAC-SHA256 work factor. */
    static final int DEFAULT_ITERATIONS = 600_000;

    private static final int SALT_BYTES = 16;
    private static final int NONCE_BYTES = 12;
    private static final int KEY_BITS = 256;
    private static final int TAG_BITS = 128;

    // Guards against a malicious file forcing either a trivial KDF or a DoS.
    private static final int MIN_ITERATIONS = 1_000;
    private static final int MAX_ITERATIONS = 10_000_000;

    private static final SecureRandom RANDOM = new SecureRandom();

    private Crypto()
    {
    }

    record Encrypted(byte[] salt, byte[] nonce, int iterations, byte[] ciphertext)
    {
    }

    static Encrypted encrypt(byte[] plaintext, char[] passphrase, int iterations)
    {
        validateIterations(iterations);

        if (passphrase == null || passphrase.length == 0)
        {
            throw new IllegalArgumentException("A passphrase is required");
        }

        byte[] salt = randomBytes(SALT_BYTES);
        byte[] nonce = randomBytes(NONCE_BYTES);

        try
        {
            byte[] ciphertext = crypt(Cipher.ENCRYPT_MODE, plaintext, passphrase, salt, nonce, iterations);
            return new Encrypted(salt, nonce, iterations, ciphertext);
        }
        catch (GeneralSecurityException e)
        {
            throw new IllegalStateException("Unable to encrypt the export: " + e.getMessage(), e);
        }
    }

    static byte[] decrypt(byte[] ciphertext, char[] passphrase, byte[] salt, byte[] nonce, int iterations)
    {
        validateIterations(iterations);

        if (passphrase == null || passphrase.length == 0)
        {
            throw new IllegalArgumentException("A passphrase is required");
        }

        if (salt == null || salt.length == 0 || nonce == null || nonce.length == 0)
        {
            throw new IllegalArgumentException("The export is missing its encryption parameters");
        }

        try
        {
            return crypt(Cipher.DECRYPT_MODE, ciphertext, passphrase, salt, nonce, iterations);
        }
        catch (AEADBadTagException e)
        {
            throw new DecryptionException("Incorrect passphrase or corrupted export file", e);
        }
        catch (GeneralSecurityException e)
        {
            throw new DecryptionException("Unable to decrypt the export: " + e.getMessage(), e);
        }
    }

    private static byte[] crypt(int mode, byte[] input, char[] passphrase, byte[] salt, byte[] nonce, int iterations)
            throws GeneralSecurityException
    {
        PBEKeySpec keySpec = new PBEKeySpec(passphrase, salt, iterations, KEY_BITS);
        byte[] key = null;

        try
        {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            key = factory.generateSecret(keySpec).getEncoded();

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
            return cipher.doFinal(input);
        }
        finally
        {
            keySpec.clearPassword();

            if (key != null)
            {
                Arrays.fill(key, (byte) 0);
            }
        }
    }

    private static void validateIterations(int iterations)
    {
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS)
        {
            throw new IllegalArgumentException("Unsupported key derivation strength: " + iterations);
        }
    }

    private static byte[] randomBytes(int length)
    {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }
}
