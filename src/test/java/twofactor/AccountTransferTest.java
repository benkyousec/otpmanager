package twofactor;

import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AccountTransferTest
{
    private static final String SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    private static final char[] PASSPHRASE = "correct-horse-battery".toCharArray();

    // Low work factor keeps the tests fast; production uses Crypto.DEFAULT_ITERATIONS.
    private static final int TEST_ITERATIONS = 1_000;

    private static TwoFactorAccount totp(String issuer, String account)
    {
        return new TwoFactorAccount(null, issuer, account, SECRET, OtpType.TOTP,
                OtpAlgorithm.SHA1, 6, 30L, 0L, 1_700_000_000_000L);
    }

    private static TwoFactorAccount hotp()
    {
        return new TwoFactorAccount(null, "Beta", "bob", SECRET, OtpType.HOTP,
                OtpAlgorithm.SHA256, 8, 30L, 42L, 1_700_000_000_000L);
    }

    @Test
    void plaintextRoundTripPreservesEverything()
    {
        List<TwoFactorAccount> original = List.of(totp("Acme", "alice"), hotp());

        String json = AccountTransfer.exportJson(original, null);
        AccountTransfer.ImportResult result = AccountTransfer.importContent(json, null);

        assertFalse(result.encrypted());
        assertEquals(2, result.accounts().size());

        TwoFactorAccount acme = result.accounts().get(0);
        assertEquals("Acme", acme.issuer());
        assertEquals("alice", acme.account());
        assertEquals(SECRET, acme.secret());
        assertEquals(OtpType.TOTP, acme.type());
        assertEquals(1_700_000_000_000L, acme.createdAt());

        TwoFactorAccount beta = result.accounts().get(1);
        assertEquals(OtpType.HOTP, beta.type());
        assertEquals(OtpAlgorithm.SHA256, beta.algorithm());
        assertEquals(8, beta.digits());
        assertEquals(42L, beta.counter());
    }

    @Test
    void encryptedRoundTripRequiresPassphrase()
    {
        String json = AccountTransfer.exportJson(List.of(totp("Acme", "alice")), PASSPHRASE, TEST_ITERATIONS);

        assertTrue(AccountTransfer.isEncrypted(json));
        assertTrue(AccountTransfer.isRecognisedFormat(json));

        AccountTransfer.ImportResult result = AccountTransfer.importContent(json, PASSPHRASE);

        assertTrue(result.encrypted());
        assertEquals(1, result.accounts().size());
        assertEquals("Acme", result.accounts().get(0).issuer());
    }

    @Test
    void encryptedExportDoesNotLeakSecretsOrLabels()
    {
        String json = AccountTransfer.exportJson(List.of(totp("Acme", "alice")), PASSPHRASE, TEST_ITERATIONS);

        assertFalse(json.contains(SECRET), "ciphertext must not contain the secret");
        assertFalse(json.contains("Acme"), "ciphertext must not contain the issuer");
        assertFalse(json.contains("alice"), "ciphertext must not contain the account name");
    }

    @Test
    void wrongPassphraseIsRejected()
    {
        String json = AccountTransfer.exportJson(List.of(totp("Acme", "alice")), PASSPHRASE, TEST_ITERATIONS);

        assertThrows(DecryptionException.class,
                () -> AccountTransfer.importContent(json, "wrong-passphrase".toCharArray()));
    }

    @Test
    void missingPassphraseForEncryptedExportIsRejected()
    {
        String json = AccountTransfer.exportJson(List.of(totp("Acme", "alice")), PASSPHRASE, TEST_ITERATIONS);

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> AccountTransfer.importContent(json, null));

        assertTrue(error.getMessage().contains("passphrase"));
        assertFalse(error instanceof DecryptionException);
    }

    @Test
    void tamperedCiphertextIsRejected()
    {
        String json = AccountTransfer.exportJson(List.of(totp("Acme", "alice")), PASSPHRASE, TEST_ITERATIONS);

        String marker = "\"payload\": \"";
        int start = json.indexOf(marker) + marker.length();
        char original = json.charAt(start);
        char replacement = original == 'A' ? 'B' : 'A';
        String tampered = json.substring(0, start) + replacement + json.substring(start + 1);

        assertThrows(DecryptionException.class,
                () -> AccountTransfer.importContent(tampered, PASSPHRASE));
    }

    @Test
    void importsUriListExport()
    {
        List<TwoFactorAccount> original = List.of(totp("Acme", "alice"), hotp());

        String text = AccountTransfer.exportUris(original);
        AccountTransfer.ImportResult result = AccountTransfer.importContent(text, null);

        assertEquals(2, result.accounts().size());
        assertEquals("Acme", result.accounts().get(0).issuer());
        assertEquals(42L, result.accounts().get(1).counter());
        assertFalse(result.encrypted());
    }

    @Test
    void importsMigrationPayload()
    {
        String migration = TestMigrationPayloads.singleAccountUri("Acme", "alice", "12345678901234567890");

        AccountTransfer.ImportResult result = AccountTransfer.importContent(migration, null);

        assertEquals(1, result.accounts().size());
        assertEquals("Acme", result.accounts().get(0).issuer());
    }

    @Test
    void importsBareSecretAsLastResort()
    {
        AccountTransfer.ImportResult result = AccountTransfer.importContent(SECRET, null);

        assertEquals(1, result.accounts().size());
        assertTrue(result.warnings().stream().anyMatch(w -> w.contains("bare Base32 secret")));
    }

    @Test
    void rejectsEmptyAndUnrecognisedContent()
    {
        assertThrows(IllegalArgumentException.class, () -> AccountTransfer.importContent("", null));
        assertThrows(IllegalArgumentException.class, () -> AccountTransfer.importContent("hello world", null));
        assertThrows(IllegalArgumentException.class, () -> AccountTransfer.importContent(null, null));
    }

    @Test
    void rejectsNewerFormatVersions()
    {
        String json = AccountTransfer.exportJson(List.of(totp("Acme", "alice")), null)
                .replace("\"version\": 1", "\"version\": 99");

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> AccountTransfer.importContent(json, null));

        assertTrue(error.getMessage().contains("newer version"));
    }

    @Test
    void reportsInvalidAccountsAsWarningsButKeepsValidOnes()
    {
        String valid = AccountTransfer.exportJson(List.of(totp("Acme", "alice")), null);
        String withBadAccount = valid.replace("\"accounts\": [",
                "\"accounts\": [\n    {\"issuer\": \"Broken\", \"secret\": \"not!base32\"},");

        AccountTransfer.ImportResult result = AccountTransfer.importContent(withBadAccount, null);

        assertEquals(1, result.accounts().size());
        assertEquals("Acme", result.accounts().get(0).issuer());
        assertEquals(1, result.warnings().size());
        assertTrue(result.warnings().get(0).contains("Skipped account"));
    }

    @Test
    void exportedJsonOmitsLocalStorageId()
    {
        String json = AccountTransfer.exportJson(List.of(totp("Acme", "alice")), null);
        assertFalse(json.contains("\"id\""));
    }

    @Test
    void encryptedEnvelopeCarriesKdfParameters()
    {
        String json = AccountTransfer.exportJson(List.of(totp("Acme", "alice")), PASSPHRASE, TEST_ITERATIONS);

        assertTrue(json.contains("\"kdf\": \"PBKDF2WithHmacSHA256\""));
        assertTrue(json.contains("\"cipher\": \"AES/GCM/NoPadding\""));
        assertTrue(json.contains("\"iterations\": " + TEST_ITERATIONS));
        assertNotNull(Base64.getMimeDecoder().decode(extract(json, "salt")));
        assertNotNull(Base64.getMimeDecoder().decode(extract(json, "nonce")));
    }

    private static String extract(String json, String field)
    {
        String marker = "\"" + field + "\": \"";
        int start = json.indexOf(marker) + marker.length();
        int end = json.indexOf('"', start);
        return json.substring(start, end);
    }
}
