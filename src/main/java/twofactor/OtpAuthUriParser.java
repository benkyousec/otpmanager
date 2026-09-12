package twofactor;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parser for the Key URI format used by Google Authenticator and compatible
 * apps: {@code otpauth://totp/Issuer:account?secret=...&issuer=...}.
 *
 * <p>Treats the input as untrusted: every field is length-checked and
 * validated, and parsing never evaluates or dereferences anything.</p>
 */
public final class OtpAuthUriParser
{
    private static final String SCHEME = "otpauth://";

    /**
     * Finds provisioning URIs inside arbitrary text (HTTP bodies, QR payloads).
     * Stops at characters that commonly terminate a URI in prose or markup.
     */
    private static final Pattern URI_PATTERN =
            Pattern.compile("(?i)otpauth(?:-migration)?://[^\\s\"'<>`\\\\()\\[\\]{},;]+");

    private static final int MAX_SECRET_CHARS = 1024;
    private static final int MAX_LABEL_CHARS = 512;

    private OtpAuthUriParser()
    {
    }

    public static boolean looksLikeOtpAuthUri(String value)
    {
        return value != null && value.trim().regionMatches(true, 0, SCHEME, 0, SCHEME.length());
    }

    /**
     * Extracts every provisioning URI found in the supplied text, in order and
     * without duplicates.
     */
    public static List<String> findUris(String text)
    {
        Set<String> found = new LinkedHashSet<>();

        if (text == null || text.isEmpty())
        {
            return new ArrayList<>();
        }

        Matcher matcher = URI_PATTERN.matcher(text);

        while (matcher.find())
        {
            String candidate = trimTrailingPunctuation(matcher.group());

            if (!candidate.isEmpty())
            {
                found.add(candidate);
            }
        }

        return new ArrayList<>(found);
    }

    /**
     * Parses one or more URIs from the supplied text, which may be a single
     * URI, several newline-separated URIs, or free-form text containing them.
     *
     * @throws IllegalArgumentException when no valid account can be parsed
     */
    public static List<TwoFactorAccount> parseAll(String text)
    {
        List<String> uris = findUris(text);

        if (uris.isEmpty())
        {
            throw new IllegalArgumentException("No otpauth:// URI was found");
        }

        List<TwoFactorAccount> accounts = new ArrayList<>();
        List<String> errors = new ArrayList<>();

        for (String uri : uris)
        {
            try
            {
                accounts.addAll(parse(uri));
            }
            catch (IllegalArgumentException e)
            {
                errors.add(e.getMessage());
            }
        }

        if (accounts.isEmpty())
        {
            throw new IllegalArgumentException(errors.isEmpty()
                    ? "No valid accounts were found"
                    : String.join("; ", errors));
        }

        return accounts;
    }

    /**
     * Parses a single provisioning URI into one or more accounts (migration
     * payloads can hold many).
     */
    public static List<TwoFactorAccount> parse(String uri)
    {
        String trimmed = uri == null ? "" : uri.trim();

        if (MigrationPayloadParser.isMigrationUri(trimmed))
        {
            return MigrationPayloadParser.parse(trimmed);
        }

        if (!trimmed.regionMatches(true, 0, SCHEME, 0, SCHEME.length()))
        {
            throw new IllegalArgumentException("Not an otpauth:// URI");
        }

        String remainder = trimmed.substring(SCHEME.length());
        int questionMark = remainder.indexOf('?');
        String path = questionMark >= 0 ? remainder.substring(0, questionMark) : remainder;
        String query = questionMark >= 0 ? remainder.substring(questionMark + 1) : "";

        int slash = path.indexOf('/');
        String typeName = slash >= 0 ? path.substring(0, slash) : path;
        String label = slash >= 0 ? path.substring(slash + 1) : "";

        OtpType type = OtpType.parse(typeName);

        if (type == null)
        {
            throw new IllegalArgumentException("Unsupported OTP type '" + typeName + "'");
        }

        Map<String, String> parameters = QueryStrings.parse(query);

        String secret = parameters.get("secret");

        if (secret == null || secret.isEmpty())
        {
            throw new IllegalArgumentException("The URI does not contain a secret");
        }

        if (secret.length() > MAX_SECRET_CHARS)
        {
            throw new IllegalArgumentException("The secret is too long");
        }

        String normalizedSecret = Base32.normalize(secret);

        try
        {
            Base32.decode(normalizedSecret);
        }
        catch (IllegalArgumentException e)
        {
            throw new IllegalArgumentException("Invalid Base32 secret: " + e.getMessage(), e);
        }

        String decodedLabel = QueryStrings.decode(label).trim();

        if (decodedLabel.length() > MAX_LABEL_CHARS)
        {
            decodedLabel = decodedLabel.substring(0, MAX_LABEL_CHARS);
        }

        String issuer = parameters.getOrDefault("issuer", "").trim();
        String account = decodedLabel;

        int separator = decodedLabel.indexOf(':');

        if (separator >= 0)
        {
            String labelIssuer = decodedLabel.substring(0, separator).trim();
            account = decodedLabel.substring(separator + 1).trim();

            if (issuer.isEmpty())
            {
                issuer = labelIssuer;
            }
        }

        OtpAlgorithm algorithm = OtpAlgorithm.SHA1;
        String algorithmParameter = parameters.get("algorithm");

        if (algorithmParameter != null && !algorithmParameter.isBlank())
        {
            OtpAlgorithm parsed = OtpAlgorithm.parse(algorithmParameter);

            if (parsed == null)
            {
                throw new IllegalArgumentException("Unsupported algorithm '" + algorithmParameter + "'");
            }

            algorithm = parsed;
        }

        int digits = parseDigits(parameters.get("digits"));
        long period = parsePeriod(parameters.get("period"));
        long counter = parseCounter(parameters.get("counter"));

        return List.of(new TwoFactorAccount(null, issuer, account, normalizedSecret, type, algorithm, digits, period, counter, 0L));
    }

    private static int parseDigits(String value)
    {
        if (value == null || value.isBlank())
        {
            return OtpCodeGenerator.DEFAULT_DIGITS;
        }

        int digits;

        try
        {
            digits = Integer.parseInt(value.trim());
        }
        catch (NumberFormatException e)
        {
            throw new IllegalArgumentException("Invalid digits value '" + value + "'");
        }

        if (!OtpCodeGenerator.isValidDigits(digits))
        {
            throw new IllegalArgumentException("Digits must be between "
                    + OtpCodeGenerator.MIN_DIGITS + " and " + OtpCodeGenerator.MAX_DIGITS);
        }

        return digits;
    }

    private static long parsePeriod(String value)
    {
        if (value == null || value.isBlank())
        {
            return OtpCodeGenerator.DEFAULT_PERIOD;
        }

        long period;

        try
        {
            period = Long.parseLong(value.trim());
        }
        catch (NumberFormatException e)
        {
            throw new IllegalArgumentException("Invalid period value '" + value + "'");
        }

        if (period <= 0 || period > 86_400L)
        {
            throw new IllegalArgumentException("The period must be between 1 and 86400 seconds");
        }

        return period;
    }

    private static long parseCounter(String value)
    {
        if (value == null || value.isBlank())
        {
            return 0L;
        }

        try
        {
            long counter = Long.parseLong(value.trim());
            return Math.max(0L, counter);
        }
        catch (NumberFormatException e)
        {
            throw new IllegalArgumentException("Invalid counter value '" + value + "'");
        }
    }

    private static String trimTrailingPunctuation(String value)
    {
        String result = value;

        while (!result.isEmpty())
        {
            char last = result.charAt(result.length() - 1);

            if (last == '.' || last == ',' || last == ';' || last == ':' || last == ')' || last == ']' || last == '}')
            {
                result = result.substring(0, result.length() - 1);
            }
            else
            {
                break;
            }
        }

        return result;
    }

    /**
     * Best-effort fallback for QR codes that contain a bare Base32 secret rather
     * than a full provisioning URI. The returned account has default TOTP
     * parameters and no label, so it is always shown to the user for review.
     */
    public static TwoFactorAccount parseBareSecret(String value)
    {
        String normalized = Base32.normalize(value);

        if (normalized.length() < 16 || normalized.length() > MAX_SECRET_CHARS)
        {
            return null;
        }

        if (!normalized.matches("[A-Z2-7]+"))
        {
            return null;
        }

        try
        {
            Base32.decode(normalized);
        }
        catch (IllegalArgumentException e)
        {
            return null;
        }

        return new TwoFactorAccount(null, "", "", normalized, OtpType.TOTP, OtpAlgorithm.SHA1,
                OtpCodeGenerator.DEFAULT_DIGITS, OtpCodeGenerator.DEFAULT_PERIOD, 0L, 0L);
    }
}
