package twofactor;

import java.util.Locale;

/**
 * HMAC algorithms permitted by the Key URI format, plus MD5 which is used by
 * some legacy Google Authenticator export payloads.
 */
public enum OtpAlgorithm
{
    SHA1("HmacSHA1", "SHA1"),
    SHA256("HmacSHA256", "SHA256"),
    SHA512("HmacSHA512", "SHA512"),
    MD5("HmacMD5", "MD5");

    private final String jcaName;
    private final String label;

    OtpAlgorithm(String jcaName, String label)
    {
        this.jcaName = jcaName;
        this.label = label;
    }

    public String jcaName()
    {
        return jcaName;
    }

    public String label()
    {
        return label;
    }

    /**
     * Parses an algorithm name from an otpauth URI. Returns {@code null} when
     * the name is not recognised so callers can decide whether to reject it.
     */
    public static OtpAlgorithm parse(String name)
    {
        if (name == null)
        {
            return null;
        }

        String cleaned = name.trim().toUpperCase(Locale.ROOT).replace("-", "").replace("_", "");

        if (cleaned.startsWith("HMAC"))
        {
            cleaned = cleaned.substring(4);
        }

        for (OtpAlgorithm algorithm : values())
        {
            if (algorithm.label.equals(cleaned))
            {
                return algorithm;
            }
        }

        return null;
    }
}
