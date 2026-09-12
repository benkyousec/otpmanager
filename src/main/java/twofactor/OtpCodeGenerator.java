package twofactor;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * HOTP (RFC 4226) and TOTP (RFC 6238) one-time password generation.
 *
 * <p>No state is held; every call is a pure function of the key and counter,
 * which keeps it trivially safe to call from the Swing event dispatch thread.</p>
 */
public final class OtpCodeGenerator
{
    private static final long[] POWERS_OF_TEN = {
            1L,
            10L,
            100L,
            1_000L,
            10_000L,
            100_000L,
            1_000_000L,
            10_000_000L,
            100_000_000L,
            1_000_000_000L,
            10_000_000_000L
    };

    public static final int MIN_DIGITS = 1;
    public static final int MAX_DIGITS = 10;
    public static final long DEFAULT_PERIOD = 30L;
    public static final int DEFAULT_DIGITS = 6;

    private OtpCodeGenerator()
    {
    }

    /**
     * Generates a HOTP code for the supplied counter.
     */
    public static String hotp(byte[] key, OtpAlgorithm algorithm, int digits, long counter)
    {
        byte[] message =
                {
                        (byte) (counter >>> 56),
                        (byte) (counter >>> 48),
                        (byte) (counter >>> 40),
                        (byte) (counter >>> 32),
                        (byte) (counter >>> 24),
                        (byte) (counter >>> 16),
                        (byte) (counter >>> 8),
                        (byte) counter
                };

        return truncate(hmac(key, algorithm, message), digits);
    }

    /**
     * Generates a TOTP code for the supplied instant (seconds since the Unix
     * epoch).
     */
    public static String totp(byte[] key, OtpAlgorithm algorithm, int digits, long period, long epochSeconds)
    {
        if (period <= 0)
        {
            throw new IllegalArgumentException("The period must be greater than zero");
        }

        return hotp(key, algorithm, digits, epochSeconds / period);
    }

    /**
     * Seconds until the current TOTP code expires (always in {@code 1..period}).
     */
    public static long secondsRemaining(long period, long epochSeconds)
    {
        if (period <= 0)
        {
            return 0;
        }

        long remaining = period - (Math.floorMod(epochSeconds, period));
        return remaining == 0 ? period : remaining;
    }

    /**
     * RFC 4226 dynamic truncation.
     */
    static String truncate(byte[] hash, int digits)
    {
        int offset = hash[hash.length - 1] & 0x0F;

        long binary =
                ((hash[offset] & 0x7F) << 24)
                        | ((hash[offset + 1] & 0xFF) << 16)
                        | ((hash[offset + 2] & 0xFF) << 8)
                        | (hash[offset + 3] & 0xFF);

        long code = binary % powerOfTen(digits);

        return String.format("%0" + digits + "d", code);
    }

    static byte[] hmac(byte[] key, OtpAlgorithm algorithm, byte[] message)
    {
        if (key == null || key.length == 0)
        {
            throw new IllegalArgumentException("The secret is empty");
        }

        try
        {
            Mac mac = Mac.getInstance(algorithm.jcaName());
            mac.init(new SecretKeySpec(key, algorithm.jcaName()));
            return mac.doFinal(message);
        }
        catch (NoSuchAlgorithmException | InvalidKeyException e)
        {
            throw new IllegalStateException("Unable to compute HMAC: " + e.getMessage(), e);
        }
    }

    public static boolean isValidDigits(int digits)
    {
        return digits >= MIN_DIGITS && digits <= MAX_DIGITS;
    }

    private static long powerOfTen(int digits)
    {
        if (!isValidDigits(digits))
        {
            throw new IllegalArgumentException("Digits must be between " + MIN_DIGITS + " and " + MAX_DIGITS);
        }

        return POWERS_OF_TEN[digits];
    }
}
