package twofactor;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Import/export of registered accounts for sharing between team members.
 *
 * <p>Two on-disk shapes are produced, both self-describing so import can
 * auto-detect them:</p>
 * <ul>
 *   <li><b>JSON envelope</b> ({@code .2fa.json}) - optionally encrypted with a
 *       passphrase. This is the recommended format because it preserves HOTP
 *       counters and metadata exactly.</li>
 *   <li><b>URI list</b> ({@code .txt}) - one {@code otpauth://} URI per line.
 *       Plaintext and interoperable with phones/other tools, but exposes the
 *       secrets.</li>
 * </ul>
 *
 * <p>Import also accepts free-form text and bare Base32 secrets as a
 * convenience. Exported JSON deliberately omits the local storage id so that
 * imported accounts always receive fresh ids.</p>
 */
public final class AccountTransfer
{
    public static final String FORMAT = "2fa-code-generator/export";
    public static final int VERSION = 1;

    private static final String KDF = "PBKDF2WithHmacSHA256";
    private static final String CIPHER = "AES/GCM/NoPadding";

    private AccountTransfer()
    {
    }

    public static String exportJson(List<TwoFactorAccount> accounts, char[] passphrase)
    {
        return exportJson(accounts, passphrase, Crypto.DEFAULT_ITERATIONS);
    }

    public static String exportJson(List<TwoFactorAccount> accounts, char[] passphrase, int iterations)
    {
        String plaintext = plaintextEnvelope(accounts);

        if (passphrase == null || passphrase.length == 0)
        {
            return plaintext;
        }

        Crypto.Encrypted encrypted = Crypto.encrypt(plaintext.getBytes(StandardCharsets.UTF_8), passphrase, iterations);

        return encryptedEnvelope(encrypted);
    }

    public static String exportUris(List<TwoFactorAccount> accounts)
    {
        StringBuilder builder = new StringBuilder();

        for (TwoFactorAccount account : accounts)
        {
            builder.append(account.toUri()).append('\n');
        }

        return builder.toString();
    }

    /**
     * True when the content is one of this extension's export envelopes.
     */
    public static boolean isRecognisedFormat(String content)
    {
        Map<String, Object> root = tryParseObject(content);
        return root != null && FORMAT.equals(Json.optString(root, "format", null));
    }

    /**
     * True when the content is an encrypted export, so the UI knows to prompt
     * for a passphrase before calling {@link #importContent}.
     */
    public static boolean isEncrypted(String content)
    {
        Map<String, Object> root = tryParseObject(content);

        return root != null
                && FORMAT.equals(Json.optString(root, "format", null))
                && Json.optBoolean(root, "encrypted", false);
    }

    /**
     * Parses accounts from an exported file or arbitrary text.
     *
     * @param content    file content
     * @param passphrase passphrase for encrypted exports, otherwise {@code null}
     * @throws DecryptionException      wrong passphrase or tampered data
     * @throws IllegalArgumentException no accounts found, or a malformed file
     */
    public static ImportResult importContent(String content, char[] passphrase)
    {
        if (content == null || content.isBlank())
        {
            throw new IllegalArgumentException("The file is empty");
        }

        List<String> warnings = new ArrayList<>();
        Map<String, Object> root = tryParseObject(content);

        if (root != null && FORMAT.equals(Json.optString(root, "format", null)))
        {
            int version = (int) Json.optLong(root, "version", VERSION);

            if (version > VERSION)
            {
                throw new IllegalArgumentException(
                        "This export was created by a newer version of the extension (format version " + version + ")");
            }

            boolean encrypted = Json.optBoolean(root, "encrypted", false);

            if (encrypted)
            {
                if (passphrase == null || passphrase.length == 0)
                {
                    throw new IllegalArgumentException("This export is encrypted and requires a passphrase");
                }

                root = decryptEnvelope(root, passphrase);
            }

            List<TwoFactorAccount> accounts = readAccounts(root, warnings);

            if (accounts.isEmpty())
            {
                throw new IllegalArgumentException(warnings.isEmpty()
                        ? "The export did not contain any accounts"
                        : String.join("; ", warnings));
            }

            return new ImportResult(List.copyOf(accounts), List.copyOf(warnings), encrypted);
        }

        List<TwoFactorAccount> accounts = parseText(content, warnings);

        if (accounts.isEmpty())
        {
            throw new IllegalArgumentException(warnings.isEmpty()
                    ? "No accounts were found in the file"
                    : String.join("; ", warnings));
        }

        return new ImportResult(List.copyOf(accounts), List.copyOf(warnings), false);
    }

    private static Map<String, Object> decryptEnvelope(Map<String, Object> root, char[] passphrase)
    {
        byte[] salt = decodeBase64(Json.optString(root, "salt", null), "salt");
        byte[] nonce = decodeBase64(Json.optString(root, "nonce", null), "nonce");
        byte[] payload = decodeBase64(Json.optString(root, "payload", null), "payload");
        int iterations = (int) Json.optLong(root, "iterations", Crypto.DEFAULT_ITERATIONS);

        byte[] plaintext = Crypto.decrypt(payload, passphrase, salt, nonce, iterations);
        Map<String, Object> decrypted = tryParseObject(new String(plaintext, StandardCharsets.UTF_8));

        if (decrypted == null)
        {
            throw new IllegalArgumentException("The decrypted export is not valid");
        }

        return decrypted;
    }

    private static List<TwoFactorAccount> readAccounts(Map<String, Object> root, List<String> warnings)
    {
        Object accountsNode = root.get("accounts");

        if (accountsNode == null)
        {
            throw new IllegalArgumentException("The export does not contain an 'accounts' list");
        }

        List<Object> nodes = Json.asArray(accountsNode, "The 'accounts' field");
        List<TwoFactorAccount> accounts = new ArrayList<>();

        for (int i = 0; i < nodes.size(); i++)
        {
            try
            {
                Map<String, Object> node = Json.asObject(nodes.get(i), "Account #" + (i + 1));
                String secret = Json.optString(node, "secret", null);

                if (secret == null || secret.isBlank())
                {
                    throw new IllegalArgumentException("missing secret");
                }

                Base32.decode(secret);

                accounts.add(new TwoFactorAccount(
                        null,
                        Json.optString(node, "issuer", ""),
                        Json.optString(node, "account", ""),
                        secret,
                        OtpType.parse(Json.optString(node, "type", "TOTP")),
                        OtpAlgorithm.parse(Json.optString(node, "algorithm", "SHA1")),
                        (int) Json.optLong(node, "digits", OtpCodeGenerator.DEFAULT_DIGITS),
                        Json.optLong(node, "period", OtpCodeGenerator.DEFAULT_PERIOD),
                        Json.optLong(node, "counter", 0L),
                        Json.optLong(node, "createdAt", 0L)));
            }
            catch (RuntimeException e)
            {
                warnings.add("Skipped account #" + (i + 1) + ": " + e.getMessage());
            }
        }

        return accounts;
    }

    private static List<TwoFactorAccount> parseText(String content, List<String> warnings)
    {
        List<TwoFactorAccount> accounts = new ArrayList<>();

        for (String uri : OtpAuthUriParser.findUris(content))
        {
            try
            {
                accounts.addAll(OtpAuthUriParser.parse(uri));
            }
            catch (IllegalArgumentException e)
            {
                warnings.add(e.getMessage());
            }
        }

        if (accounts.isEmpty() && content.length() <= 512)
        {
            TwoFactorAccount bare = OtpAuthUriParser.parseBareSecret(content.trim());

            if (bare != null)
            {
                accounts.add(bare);
                warnings.add("A bare Base32 secret was found with no issuer or account name.");
            }
        }

        return accounts;
    }

    private static String plaintextEnvelope(List<TwoFactorAccount> accounts)
    {
        StringBuilder builder = new StringBuilder();
        builder.append("{\n");
        builder.append("  \"format\": \"").append(FORMAT).append("\",\n");
        builder.append("  \"version\": ").append(VERSION).append(",\n");
        builder.append("  \"encrypted\": false,\n");
        builder.append("  \"generator\": \"2FA Code Generator\",\n");
        builder.append("  \"exportedAt\": ").append(System.currentTimeMillis()).append(",\n");
        builder.append("  \"accounts\": [");

        for (int i = 0; i < accounts.size(); i++)
        {
            builder.append(i == 0 ? "\n" : ",\n");
            builder.append("    ").append(accountJson(accounts.get(i)));
        }

        if (!accounts.isEmpty())
        {
            builder.append('\n');
        }

        builder.append("  ]\n");
        builder.append("}\n");
        return builder.toString();
    }

    private static String encryptedEnvelope(Crypto.Encrypted encrypted)
    {
        StringBuilder builder = new StringBuilder();
        builder.append("{\n");
        builder.append("  \"format\": \"").append(FORMAT).append("\",\n");
        builder.append("  \"version\": ").append(VERSION).append(",\n");
        builder.append("  \"encrypted\": true,\n");
        builder.append("  \"generator\": \"2FA Code Generator\",\n");
        builder.append("  \"exportedAt\": ").append(System.currentTimeMillis()).append(",\n");
        builder.append("  \"kdf\": \"").append(KDF).append("\",\n");
        builder.append("  \"iterations\": ").append(encrypted.iterations()).append(",\n");
        builder.append("  \"cipher\": \"").append(CIPHER).append("\",\n");
        builder.append("  \"salt\": \"").append(encodeBase64(encrypted.salt())).append("\",\n");
        builder.append("  \"nonce\": \"").append(encodeBase64(encrypted.nonce())).append("\",\n");
        builder.append("  \"payload\": \"").append(encodeBase64(encrypted.ciphertext())).append("\"\n");
        builder.append("}\n");
        return builder.toString();
    }

    private static String accountJson(TwoFactorAccount account)
    {
        StringBuilder builder = new StringBuilder();
        builder.append('{');
        builder.append("\"issuer\": \"").append(Json.escape(account.issuer())).append("\", ");
        builder.append("\"account\": \"").append(Json.escape(account.account())).append("\", ");
        builder.append("\"secret\": \"").append(Json.escape(account.secret())).append("\", ");
        builder.append("\"type\": \"").append(account.type().name()).append("\", ");
        builder.append("\"algorithm\": \"").append(account.algorithm().name()).append("\", ");
        builder.append("\"digits\": ").append(account.digits()).append(", ");
        builder.append("\"period\": ").append(account.period()).append(", ");
        builder.append("\"counter\": ").append(account.counter()).append(", ");
        builder.append("\"createdAt\": ").append(account.createdAt());
        builder.append('}');
        return builder.toString();
    }

    private static Map<String, Object> tryParseObject(String content)
    {
        if (content == null)
        {
            return null;
        }

        String trimmed = content.trim();

        if (!trimmed.startsWith("{"))
        {
            return null;
        }

        try
        {
            return Json.asObject(Json.parse(trimmed), "The export file");
        }
        catch (RuntimeException e)
        {
            return null;
        }
    }

    private static String encodeBase64(byte[] data)
    {
        return Base64.getEncoder().encodeToString(data);
    }

    private static byte[] decodeBase64(String value, String field)
    {
        if (value == null || value.isBlank())
        {
            throw new IllegalArgumentException("The export is missing its '" + field + "' value");
        }

        try
        {
            return Base64.getMimeDecoder().decode(value);
        }
        catch (IllegalArgumentException e)
        {
            throw new IllegalArgumentException("The export has an invalid '" + field + "' value", e);
        }
    }

    public record ImportResult(List<TwoFactorAccount> accounts, List<String> warnings, boolean encrypted)
    {
    }
}
