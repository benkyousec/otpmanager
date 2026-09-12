package twofactor;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration tests for extracting provisioning data from raw response bodies.
 */
class ResponseScannerTest
{
    private static final String SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    private static final String URI = "otpauth://totp/Acme:alice?secret=" + SECRET + "&issuer=Acme";

    @Test
    void findsOtpAuthUriInJson()
    {
        String json = "{\"otpauth_url\":\"" + URI + "\",\"status\":\"ok\"}";

        ResponseScanner.ScanResult result = ResponseScanner.scanBody(bytes(json), false);

        assertEquals(1, result.accounts().size());
        assertEquals("Acme", result.accounts().get(0).issuer());
        assertEquals("alice", result.accounts().get(0).account());
    }

    @Test
    void findsMultipleUrisAndDeduplicates()
    {
        String body = URI + "\n" + URI + "\n"
                + "otpauth://totp/Beta:bob?secret=" + SECRET + "&issuer=Beta";

        ResponseScanner.ScanResult result = ResponseScanner.scanBody(bytes(body), false);

        assertEquals(2, result.accounts().size());
    }

    @Test
    void decodesQrImageResponse()
    {
        ResponseScanner.ScanResult result = ResponseScanner.scanBody(TestQrCodes.png(URI, 260), true);

        assertEquals(1, result.accounts().size());
        assertEquals("Acme", result.accounts().get(0).issuer());
        assertEquals("alice", result.accounts().get(0).account());
    }

    @Test
    void decodesQrCodeEmbeddedAsDataUri()
    {
        String base64 = Base64.getEncoder().encodeToString(TestQrCodes.png(URI, 260));
        String html = "<html><body><img src=\"data:image/png;base64," + base64 + "\"></body></html>";

        ResponseScanner.ScanResult result = ResponseScanner.scanBody(bytes(html), false);

        assertEquals(1, result.accounts().size());
        assertEquals("Acme", result.accounts().get(0).issuer());
    }

    @Test
    void parsesMigrationPayloadInText()
    {
        String uri = TestMigrationPayloads.singleAccountUri("Acme", "alice", "12345678901234567890");

        ResponseScanner.ScanResult result = ResponseScanner.scanBody(bytes("{\"qr\":\"" + uri + "\"}"), false);

        assertEquals(1, result.accounts().size());
        assertEquals("Acme", result.accounts().get(0).issuer());
    }

    @Test
    void fallsBackToBareSecretInShortBody()
    {
        ResponseScanner.ScanResult result = ResponseScanner.scanBody(bytes(SECRET), false);

        assertEquals(1, result.accounts().size());
        assertEquals(SECRET, result.accounts().get(0).secret());
        assertTrue(result.notes().stream().anyMatch(note -> note.contains("bare Base32 secret")));
    }

    @Test
    void ignoresBodiesWithoutProvisioningData()
    {
        assertTrue(ResponseScanner.scanBody(bytes("hello world"), false).isEmpty());
        assertTrue(ResponseScanner.scanBody(new byte[0], false).isEmpty());
        assertTrue(ResponseScanner.scanBody(null, false).isEmpty());
        assertTrue(ResponseScanner.scanBody(bytes("{\"a\":1}"), false).notes().isEmpty());
    }

    private static byte[] bytes(String value)
    {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
