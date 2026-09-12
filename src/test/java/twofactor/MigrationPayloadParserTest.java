package twofactor;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The migration payload is a protobuf; {@link TestMigrationPayloads} builds one
 * with a hand-rolled encoder so the parser is tested against real wire bytes.
 */
class MigrationPayloadParserTest
{
    @Test
    void parsesGoogleAuthenticatorExport()
    {
        byte[] secretOne = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
        byte[] secretTwo = "abcdefghijklmnop".getBytes(StandardCharsets.US_ASCII);

        byte[] parametersOne = TestMigrationPayloads.parameters(secretOne, "Acme:alice", "Acme", 1, 1, 2, 0L);
        byte[] parametersTwo = TestMigrationPayloads.parameters(secretTwo, "bob", "Beta", 2, 2, 1, 7L);

        String uri = TestMigrationPayloads.uri(parametersOne, parametersTwo);

        List<TwoFactorAccount> accounts = MigrationPayloadParser.parse(uri);

        assertEquals(2, accounts.size());

        TwoFactorAccount first = accounts.get(0);
        assertEquals("Acme", first.issuer());
        assertEquals("alice", first.account());
        assertEquals(Base32.encode(secretOne), first.secret());
        assertEquals(OtpType.TOTP, first.type());
        assertEquals(OtpAlgorithm.SHA1, first.algorithm());
        assertEquals(6, first.digits());

        TwoFactorAccount second = accounts.get(1);
        assertEquals("Beta", second.issuer());
        assertEquals("bob", second.account());
        assertEquals(OtpType.HOTP, second.type());
        assertEquals(OtpAlgorithm.SHA256, second.algorithm());
        assertEquals(8, second.digits());
        assertEquals(7L, second.counter());
    }

    @Test
    void splitsIssuerFromNameWhenIssuerFieldMissing()
    {
        byte[] parameters = TestMigrationPayloads.parameters(
                "abcdefghijklmnop".getBytes(StandardCharsets.US_ASCII), "Acme:alice", "", 1, 1, 2, 0L);

        TwoFactorAccount account = MigrationPayloadParser.parse(TestMigrationPayloads.uri(parameters)).get(0);

        assertEquals("Acme", account.issuer());
        assertEquals("alice", account.account());
    }

    @Test
    void isDetectedThroughOtpAuthUriParser()
    {
        byte[] parameters = TestMigrationPayloads.parameters(
                "abcdefghijklmnop".getBytes(StandardCharsets.US_ASCII), "Acme:alice", "Acme", 1, 1, 2, 0L);

        List<TwoFactorAccount> accounts = OtpAuthUriParser.parse(TestMigrationPayloads.uri(parameters));
        assertEquals(1, accounts.size());
    }

    @Test
    void rejectsInvalidPayloads()
    {
        assertThrows(IllegalArgumentException.class,
                () -> MigrationPayloadParser.parse("otpauth-migration://offline"));
        assertThrows(IllegalArgumentException.class,
                () -> MigrationPayloadParser.parse("otpauth-migration://offline?data=!!!!"));
        assertThrows(IllegalArgumentException.class,
                () -> MigrationPayloadParser.parse("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
    }
}
