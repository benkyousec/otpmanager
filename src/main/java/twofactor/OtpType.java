package twofactor;

import java.util.Locale;

public enum OtpType
{
    TOTP,
    HOTP;

    public static OtpType parse(String name)
    {
        if (name == null)
        {
            return null;
        }

        try
        {
            return valueOf(name.trim().toUpperCase(Locale.ROOT));
        }
        catch (IllegalArgumentException e)
        {
            return null;
        }
    }
}
