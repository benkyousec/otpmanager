package twofactor;

/**
 * Thrown when an encrypted export cannot be decrypted, which normally means the
 * passphrase was wrong but can also indicate a corrupted or tampered file.
 */
public class DecryptionException extends IllegalArgumentException
{
    public DecryptionException(String message, Throwable cause)
    {
        super(message, cause);
    }
}
