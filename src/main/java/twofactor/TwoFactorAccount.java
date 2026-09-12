package twofactor;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Objects;

/**
 * A single registered TOTP/HOTP account.
 *
 * <p>Instances are mutable only through the setters used by the editor dialog;
 * the UI treats them as value objects. The decoded HMAC key is cached lazily
 * and never persisted in a decoded form.</p>
 */
public final class TwoFactorAccount
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private final String id;
    private String issuer;
    private String account;
    private String secret;
    private OtpType type;
    private OtpAlgorithm algorithm;
    private int digits;
    private long period;
    private long counter;
    private long createdAt;

    private transient byte[] cachedKey;

    public TwoFactorAccount(String id,
                            String issuer,
                            String account,
                            String secret,
                            OtpType type,
                            OtpAlgorithm algorithm,
                            int digits,
                            long period,
                            long counter,
                            long createdAt)
    {
        this.id = (id == null || id.isBlank()) ? newId() : id;
        this.issuer = safeTrim(issuer);
        this.account = safeTrim(account);
        this.secret = Base32.normalize(secret);
        this.type = type == null ? OtpType.TOTP : type;
        this.algorithm = algorithm == null ? OtpAlgorithm.SHA1 : algorithm;
        this.digits = OtpCodeGenerator.isValidDigits(digits) ? digits : OtpCodeGenerator.DEFAULT_DIGITS;
        this.period = period > 0 ? period : OtpCodeGenerator.DEFAULT_PERIOD;
        this.counter = Math.max(0L, counter);
        this.createdAt = createdAt > 0 ? createdAt : System.currentTimeMillis();
    }

    public static String newId()
    {
        byte[] bytes = new byte[8];
        RANDOM.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    public String id()
    {
        return id;
    }

    public String issuer()
    {
        return issuer;
    }

    public void setIssuer(String issuer)
    {
        this.issuer = safeTrim(issuer);
    }

    public String account()
    {
        return account;
    }

    public void setAccount(String account)
    {
        this.account = safeTrim(account);
    }

    public String secret()
    {
        return secret;
    }

    public void setSecret(String secret)
    {
        this.secret = Base32.normalize(secret);
        this.cachedKey = null;
    }

    public OtpType type()
    {
        return type;
    }

    public void setType(OtpType type)
    {
        this.type = type == null ? OtpType.TOTP : type;
    }

    public OtpAlgorithm algorithm()
    {
        return algorithm;
    }

    public void setAlgorithm(OtpAlgorithm algorithm)
    {
        this.algorithm = algorithm == null ? OtpAlgorithm.SHA1 : algorithm;
    }

    public int digits()
    {
        return digits;
    }

    public void setDigits(int digits)
    {
        if (!OtpCodeGenerator.isValidDigits(digits))
        {
            throw new IllegalArgumentException("Digits must be between "
                    + OtpCodeGenerator.MIN_DIGITS + " and " + OtpCodeGenerator.MAX_DIGITS);
        }

        this.digits = digits;
    }

    public long period()
    {
        return period;
    }

    public void setPeriod(long period)
    {
        if (period <= 0)
        {
            throw new IllegalArgumentException("The period must be greater than zero");
        }

        this.period = period;
    }

    public long counter()
    {
        return counter;
    }

    public void setCounter(long counter)
    {
        this.counter = Math.max(0L, counter);
    }

    public void incrementCounter()
    {
        if (counter < Long.MAX_VALUE)
        {
            counter++;
        }
    }

    public long createdAt()
    {
        return createdAt;
    }

    public void setCreatedAt(long createdAt)
    {
        this.createdAt = createdAt;
    }

    /**
     * The decoded HMAC key, decoded on first use.
     */
    public synchronized byte[] key()
    {
        if (cachedKey == null)
        {
            cachedKey = Base32.decode(secret);
        }

        return cachedKey;
    }

    public String currentCode(long epochSeconds)
    {
        try
        {
            byte[] key = key();

            if (type == OtpType.HOTP)
            {
                return OtpCodeGenerator.hotp(key, algorithm, digits, counter);
            }

            return OtpCodeGenerator.totp(key, algorithm, digits, period, epochSeconds);
        }
        catch (RuntimeException e)
        {
            return "!".repeat(Math.max(1, digits));
        }
    }

    public long secondsRemaining(long epochSeconds)
    {
        return type == OtpType.TOTP ? OtpCodeGenerator.secondsRemaining(period, epochSeconds) : 0L;
    }

    public String displayName()
    {
        if (!issuer.isEmpty() && !account.isEmpty())
        {
            return issuer + ": " + account;
        }

        if (!issuer.isEmpty())
        {
            return issuer;
        }

        if (!account.isEmpty())
        {
            return account;
        }

        return "(unnamed)";
    }

    public String configSummary()
    {
        String base = algorithm.label() + " · " + digits + " digits";

        if (type == OtpType.HOTP)
        {
            return base + " · counter " + counter;
        }

        return base + " · " + period + "s";
    }

    /**
     * Two accounts are considered duplicates when they would generate the same
     * codes, i.e. same secret, type, digits, algorithm and (for TOTP) period.
     */
    public boolean isDuplicateOf(TwoFactorAccount other)
    {
        return other != null
                && type == other.type
                && algorithm == other.algorithm
                && digits == other.digits
                && (type != OtpType.TOTP || period == other.period)
                && secret.equalsIgnoreCase(other.secret);
    }

    /**
     * Serialises the account back to a Key URI, for export/backup.
     */
    public String toUri()
    {
        StringBuilder builder = new StringBuilder("otpauth://");
        builder.append(type == OtpType.HOTP ? "hotp" : "totp").append('/');

        String label = !issuer.isEmpty() ? issuer + ":" + account : account;
        builder.append(percentEncode(label));

        builder.append("?secret=").append(percentEncode(secret));

        if (!issuer.isEmpty())
        {
            builder.append("&issuer=").append(percentEncode(issuer));
        }

        builder.append("&algorithm=").append(algorithm.label());
        builder.append("&digits=").append(digits);

        if (type == OtpType.HOTP)
        {
            builder.append("&counter=").append(counter);
        }
        else
        {
            builder.append("&period=").append(period);
        }

        return builder.toString();
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }

        if (!(o instanceof TwoFactorAccount other))
        {
            return false;
        }

        return id.equals(other.id);
    }

    @Override
    public int hashCode()
    {
        return Objects.hash(id);
    }

    @Override
    public String toString()
    {
        return displayName();
    }

    private static String percentEncode(String value)
    {
        try
        {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.name()).replace("+", "%20");
        }
        catch (UnsupportedEncodingException e)
        {
            return value;
        }
    }

    private static String safeTrim(String value)
    {
        return value == null ? "" : value.trim();
    }
}
