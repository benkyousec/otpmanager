package twofactor;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Extracts 2FA provisioning material from an HTTP response: QR code images,
 * {@code otpauth://} URIs in text bodies, base64 data-URI images and bare
 * Base32 secrets.
 *
 * <p>The response body is untrusted input. Nothing here is executed, and all
 * findings are returned to the UI for explicit user confirmation before an
 * account is registered.</p>
 */
public final class ResponseScanner
{
    private static final int MAX_TEXT_SCAN_BYTES = 4 * 1024 * 1024;
    private static final int MAX_IMAGE_BYTES = 16 * 1024 * 1024;
    private static final int MAX_RESPONSES = 50;
    private static final int MAX_BARE_SECRET_BODY = 512;

    private ResponseScanner()
    {
    }

    public static ScanResult scan(List<HttpRequestResponse> candidates)
    {
        ScanResult result = new ScanResult();

        if (candidates == null || candidates.isEmpty())
        {
            return result;
        }

        int inspected = 0;

        for (HttpRequestResponse requestResponse : candidates)
        {
            if (requestResponse == null || !requestResponse.hasResponse())
            {
                continue;
            }

            if (inspected >= MAX_RESPONSES)
            {
                result.notes.add("Only the first " + MAX_RESPONSES + " responses were inspected.");
                break;
            }

            inspected++;
            scanResponse(requestResponse.response(), result);
        }

        result.responsesInspected = inspected;
        return result;
    }

    private static void scanResponse(HttpResponse response, ScanResult result)
    {
        scanIntoBody(safeBody(response), isImageMimeType(response), result);
    }

    /**
     * Scans a single response body. Exposed separately so the extraction logic
     * can be tested without constructing Montoya objects.
     *
     * @param body           raw response body
     * @param imageMimeType  whether the response advertised an image MIME type
     */
    public static ScanResult scanBody(byte[] body, boolean imageMimeType)
    {
        ScanResult result = new ScanResult();
        scanIntoBody(body == null ? new byte[0] : body, imageMimeType, result);
        result.responsesInspected = 1;
        return result;
    }

    private static void scanIntoBody(byte[] body, boolean imageMimeType, ScanResult result)
    {
        if (body.length == 0)
        {
            return;
        }

        boolean found = false;
        boolean binaryImage = QrDecoder.looksLikeImage(body);

        // 1. The response may itself be a QR code image.
        if (binaryImage || imageMimeType)
        {
            if (body.length <= MAX_IMAGE_BYTES)
            {
                found |= addDecoded(result, QrDecoder.decodeImageBytes(body));
            }
            else
            {
                result.notes.add("Skipped an image response larger than "
                        + (MAX_IMAGE_BYTES / (1024 * 1024)) + " MB.");
            }
        }

        if (binaryImage)
        {
            // Binary image data is not meaningful to scan as text.
            return;
        }

        // 2. Text bodies: provisioning URIs and embedded data-URI images.
        String text = textOf(body);

        if (text.isEmpty())
        {
            return;
        }

        for (String uri : OtpAuthUriParser.findUris(text))
        {
            found |= addCandidate(result, uri);
        }

        found |= addDecoded(result, QrDecoder.decodeDataUriImages(text));

        // 3. As a last resort, treat a short body as a bare Base32 secret.
        if (!found && text.length() <= MAX_BARE_SECRET_BODY)
        {
            TwoFactorAccount bare = OtpAuthUriParser.parseBareSecret(text.trim());

            if (bare != null)
            {
                result.accounts.add(bare);
                result.notes.add("A bare Base32 secret was found with no issuer or account name.");
            }
        }
    }

    private static boolean addDecoded(ScanResult result, List<String> decodedTexts)
    {
        boolean found = false;

        for (String decoded : decodedTexts)
        {
            found |= addCandidate(result, decoded);
        }

        return found;
    }

    /**
     * Turns one piece of decoded text into one or more accounts.
     *
     * @return true when at least one account was parsed
     */
    private static boolean addCandidate(ScanResult result, String text)
    {
        if (text == null || text.isBlank())
        {
            return false;
        }

        String trimmed = text.trim();
        List<String> uris;

        if (MigrationPayloadParser.isMigrationUri(trimmed) || OtpAuthUriParser.looksLikeOtpAuthUri(trimmed))
        {
            uris = List.of(trimmed);
        }
        else
        {
            uris = OtpAuthUriParser.findUris(trimmed);
        }

        boolean found = false;

        for (String uri : uris)
        {
            try
            {
                List<TwoFactorAccount> parsed = OtpAuthUriParser.parse(uri);

                if (!parsed.isEmpty())
                {
                    result.accounts.addAll(parsed);
                    found = true;
                }
            }
            catch (IllegalArgumentException e)
            {
                result.notes.add("Could not parse provisioning URI: " + e.getMessage());
            }
        }

        return found;
    }

    private static byte[] safeBody(HttpResponse response)
    {
        try
        {
            if (response.body() == null)
            {
                return new byte[0];
            }

            return response.body().getBytes();
        }
        catch (RuntimeException e)
        {
            return new byte[0];
        }
    }

    private static String textOf(byte[] body)
    {
        int length = Math.min(body.length, MAX_TEXT_SCAN_BYTES);
        return length == 0 ? "" : new String(body, 0, length, StandardCharsets.UTF_8);
    }

    private static boolean isImageMimeType(HttpResponse response)
    {
        try
        {
            return response.mimeType() != null && response.mimeType().name().startsWith("IMAGE_");
        }
        catch (RuntimeException e)
        {
            return false;
        }
    }

    public static final class ScanResult
    {
        private final List<TwoFactorAccount> accounts = new ArrayList<>();
        private final List<String> notes = new ArrayList<>();

        private int responsesInspected;

        public List<TwoFactorAccount> accounts()
        {
            return List.copyOf(deduplicate());
        }

        public List<String> notes()
        {
            return List.copyOf(notes);
        }

        public int responsesInspected()
        {
            return responsesInspected;
        }

        public boolean isEmpty()
        {
            return accounts.isEmpty();
        }

        private List<TwoFactorAccount> deduplicate()
        {
            Map<String, TwoFactorAccount> unique = new LinkedHashMap<>();

            for (TwoFactorAccount account : accounts)
            {
                unique.putIfAbsent(account.secret() + "|" + account.issuer() + "|" + account.account()
                        + "|" + account.type().name() + "|" + account.algorithm().name()
                        + "|" + account.digits(), account);
            }

            return new ArrayList<>(unique.values());
        }
    }
}
