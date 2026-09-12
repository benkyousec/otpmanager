package twofactor;

import java.io.ByteArrayOutputStream;

/**
 * RFC 4648 Base32 encoding/decoding as used by TOTP/HOTP shared secrets.
 *
 * <p>Decoding is deliberately forgiving: lowercase letters, whitespace, dashes
 * and {@code =} padding are all tolerated, because authenticator provisioning
 * URIs in the wild use all of those forms.</p>
 */
public final class Base32
{
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private Base32()
    {
    }

    /**
     * Upper-cases the input and removes characters that are not part of the
     * Base32 alphabet. Returns the canonical form used for storage.
     */
    public static String normalize(String input)
    {
        if (input == null)
        {
            return "";
        }

        StringBuilder builder = new StringBuilder(input.length());

        for (int i = 0; i < input.length(); i++)
        {
            char c = input.charAt(i);

            if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '-' || c == '=')
            {
                continue;
            }

            builder.append(Character.toUpperCase(c));
        }

        return builder.toString();
    }

    public static byte[] decode(String input)
    {
        String normalized = normalize(input);

        if (normalized.isEmpty())
        {
            throw new IllegalArgumentException("The secret is empty");
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream((normalized.length() * 5 / 8) + 1);

        int buffer = 0;
        int bitsLeft = 0;

        for (int i = 0; i < normalized.length(); i++)
        {
            char c = normalized.charAt(i);
            int value = valueOf(c);

            if (value < 0)
            {
                throw new IllegalArgumentException("Invalid Base32 character '" + c + "'");
            }

            buffer = (buffer << 5) | value;
            bitsLeft += 5;

            if (bitsLeft >= 8)
            {
                bitsLeft -= 8;
                out.write((buffer >> bitsLeft) & 0xFF);
            }
        }

        byte[] decoded = out.toByteArray();

        if (decoded.length == 0)
        {
            throw new IllegalArgumentException("The secret is too short");
        }

        return decoded;
    }

    public static String encode(byte[] data)
    {
        if (data == null || data.length == 0)
        {
            return "";
        }

        StringBuilder builder = new StringBuilder((data.length * 8 + 4) / 5);

        int buffer = 0;
        int bitsLeft = 0;

        for (byte b : data)
        {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;

            while (bitsLeft >= 5)
            {
                bitsLeft -= 5;
                builder.append(ALPHABET.charAt((buffer >> bitsLeft) & 0x1F));
            }
        }

        if (bitsLeft > 0)
        {
            builder.append(ALPHABET.charAt((buffer << (5 - bitsLeft)) & 0x1F));
        }

        while (builder.length() % 8 != 0)
        {
            builder.append('=');
        }

        return builder.toString();
    }

    private static int valueOf(char c)
    {
        if (c >= 'A' && c <= 'Z')
        {
            return c - 'A';
        }

        if (c >= '2' && c <= '7')
        {
            return c - '2' + 26;
        }

        return -1;
    }
}
