package twofactor;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Parses {@code otpauth-migration://offline?data=...} URIs, which is the format
 * produced by Google Authenticator's "Export accounts" feature.
 *
 * <p>The {@code data} parameter is a base64-encoded protobuf. Only the small
 * subset of protobuf needed to read {@code MigrationPayload} is implemented
 * here, which avoids pulling in a protobuf runtime. Unknown fields and wire
 * types are skipped so that future additions do not break parsing.</p>
 */
public final class MigrationPayloadParser
{
    private static final String SCHEME = "otpauth-migration://";

    private MigrationPayloadParser()
    {
    }

    public static boolean isMigrationUri(String uri)
    {
        return uri != null && uri.regionMatches(true, 0, SCHEME, 0, SCHEME.length());
    }

    public static List<TwoFactorAccount> parse(String uri)
    {
        String trimmed = uri == null ? "" : uri.trim();

        if (!isMigrationUri(trimmed))
        {
            throw new IllegalArgumentException("Not an otpauth-migration:// URI");
        }

        int questionMark = trimmed.indexOf('?');
        String query = questionMark >= 0 ? trimmed.substring(questionMark + 1) : "";
        String data = QueryStrings.parse(query).get("data");

        if (data == null || data.isEmpty())
        {
            throw new IllegalArgumentException("The migration URI does not contain a 'data' parameter");
        }

        byte[] payload;

        try
        {
            payload = decodeBase64Url(data);
        }
        catch (IllegalArgumentException e)
        {
            throw new IllegalArgumentException("The migration payload is not valid base64", e);
        }

        List<TwoFactorAccount> accounts = new ArrayList<>();
        ProtoReader reader = new ProtoReader(payload);

        while (reader.hasRemaining())
        {
            long tag = reader.readVarint();
            int field = (int) (tag >>> 3);
            int wireType = (int) (tag & 0x07);

            if (field == 1 && wireType == 2)
            {
                TwoFactorAccount account = parseParameters(reader.readBytes());

                if (account != null)
                {
                    accounts.add(account);
                }
            }
            else
            {
                reader.skip(wireType);
            }
        }

        if (accounts.isEmpty())
        {
            throw new IllegalArgumentException("The migration payload did not contain any accounts");
        }

        return accounts;
    }

    private static TwoFactorAccount parseParameters(byte[] encoded)
    {
        ProtoReader reader = new ProtoReader(encoded);

        byte[] secret = null;
        String name = "";
        String issuer = "";
        OtpAlgorithm algorithm = OtpAlgorithm.SHA1;
        int digits = OtpCodeGenerator.DEFAULT_DIGITS;
        OtpType type = OtpType.TOTP;
        long counter = 0L;

        while (reader.hasRemaining())
        {
            long tag = reader.readVarint();
            int field = (int) (tag >>> 3);
            int wireType = (int) (tag & 0x07);

            switch (field)
            {
                case 1 ->
                {
                    if (wireType == 2)
                    {
                        secret = reader.readBytes();
                    }
                    else
                    {
                        reader.skip(wireType);
                    }
                }
                case 2 ->
                {
                    if (wireType == 2)
                    {
                        name = new String(reader.readBytes(), StandardCharsets.UTF_8);
                    }
                    else
                    {
                        reader.skip(wireType);
                    }
                }
                case 3 ->
                {
                    if (wireType == 2)
                    {
                        issuer = new String(reader.readBytes(), StandardCharsets.UTF_8);
                    }
                    else
                    {
                        reader.skip(wireType);
                    }
                }
                case 4 ->
                {
                    if (wireType == 0)
                    {
                        algorithm = algorithmFromEnum((int) reader.readVarint());
                    }
                    else
                    {
                        reader.skip(wireType);
                    }
                }
                case 5 ->
                {
                    if (wireType == 0)
                    {
                        digits = digitsFromEnum((int) reader.readVarint());
                    }
                    else
                    {
                        reader.skip(wireType);
                    }
                }
                case 6 ->
                {
                    if (wireType == 0)
                    {
                        type = typeFromEnum((int) reader.readVarint());
                    }
                    else
                    {
                        reader.skip(wireType);
                    }
                }
                case 7 ->
                {
                    if (wireType == 0)
                    {
                        counter = reader.readVarint();
                    }
                    else
                    {
                        reader.skip(wireType);
                    }
                }
                default -> reader.skip(wireType);
            }
        }

        if (secret == null || secret.length == 0)
        {
            return null;
        }

        String accountName = name;

        if (!issuer.isEmpty())
        {
            accountName = stripIssuerPrefix(name, issuer);
        }
        else
        {
            int separator = name.indexOf(':');

            if (separator > 0)
            {
                issuer = name.substring(0, separator).trim();
                accountName = name.substring(separator + 1).trim();
            }
        }

        return new TwoFactorAccount(
                null,
                issuer,
                accountName,
                Base32.encode(secret),
                type,
                algorithm,
                digits,
                0L,
                counter,
                0L);
    }

    private static String stripIssuerPrefix(String name, String issuer)
    {
        String trimmed = name.trim();
        String prefix = issuer.trim() + ":";

        if (trimmed.regionMatches(true, 0, prefix, 0, prefix.length()))
        {
            return trimmed.substring(prefix.length()).trim();
        }

        return trimmed;
    }

    private static OtpAlgorithm algorithmFromEnum(int value)
    {
        return switch (value)
        {
            case 2 -> OtpAlgorithm.SHA256;
            case 3 -> OtpAlgorithm.SHA512;
            case 4 -> OtpAlgorithm.MD5;
            default -> OtpAlgorithm.SHA1;
        };
    }

    private static int digitsFromEnum(int value)
    {
        return value == 2 ? 8 : OtpCodeGenerator.DEFAULT_DIGITS;
    }

    private static OtpType typeFromEnum(int value)
    {
        return value == 1 ? OtpType.HOTP : OtpType.TOTP;
    }

    static byte[] decodeBase64Url(String value)
    {
        String cleaned = value.replaceAll("\\s", "").replace('-', '+').replace('_', '/');

        int remainder = cleaned.length() % 4;

        if (remainder == 2)
        {
            cleaned = cleaned + "==";
        }
        else if (remainder == 3)
        {
            cleaned = cleaned + "=";
        }
        else if (remainder == 1)
        {
            throw new IllegalArgumentException("Invalid base64 length");
        }

        return Base64.getDecoder().decode(cleaned);
    }

    /**
     * Minimal protobuf wire reader supporting varints and length-delimited
     * fields, which is everything the migration payload uses.
     */
    private static final class ProtoReader
    {
        private final byte[] data;
        private int position;

        private ProtoReader(byte[] data)
        {
            this.data = data;
        }

        private boolean hasRemaining()
        {
            return position < data.length;
        }

        private long readVarint()
        {
            long result = 0L;
            int shift = 0;

            while (true)
            {
                if (position >= data.length)
                {
                    throw new IllegalArgumentException("Truncated protobuf varint");
                }

                byte b = data[position++];
                result |= (long) (b & 0x7F) << shift;

                if ((b & 0x80) == 0)
                {
                    return result;
                }

                shift += 7;

                if (shift > 63)
                {
                    throw new IllegalArgumentException("Malformed protobuf varint");
                }
            }
        }

        private byte[] readBytes()
        {
            int length = (int) readVarint();

            if (length < 0 || position + length > data.length)
            {
                throw new IllegalArgumentException("Truncated protobuf field");
            }

            byte[] value = new byte[length];
            System.arraycopy(data, position, value, 0, length);
            position += length;
            return value;
        }

        private void skip(int wireType)
        {
            switch (wireType)
            {
                case 0 -> readVarint();
                case 1 -> advance(8);
                case 2 -> advance((int) readVarint());
                case 5 -> advance(4);
                default -> throw new IllegalArgumentException("Unsupported protobuf wire type " + wireType);
            }
        }

        private void advance(int count)
        {
            if (count < 0 || position + count > data.length)
            {
                throw new IllegalArgumentException("Truncated protobuf field");
            }

            position += count;
        }
    }

}
