package twofactor;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OtpAuthUriParserTest
{
    private static final String SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    @Test
    void parsesFullTotpUri()
    {
        List<TwoFactorAccount> accounts = OtpAuthUriParser.parse(
                "otpauth://totp/Acme:alice@example.com?secret=" + SECRET
                        + "&issuer=Acme&algorithm=SHA256&digits=8&period=60");

        assertEquals(1, accounts.size());

        TwoFactorAccount account = accounts.get(0);
        assertEquals("Acme", account.issuer());
        assertEquals("alice@example.com", account.account());
        assertEquals(SECRET, account.secret());
        assertEquals(OtpType.TOTP, account.type());
        assertEquals(OtpAlgorithm.SHA256, account.algorithm());
        assertEquals(8, account.digits());
        assertEquals(60L, account.period());
    }

    @Test
    void appliesDefaults()
    {
        TwoFactorAccount account = OtpAuthUriParser.parse("otpauth://totp/alice?secret=" + SECRET).get(0);

        assertEquals("", account.issuer());
        assertEquals("alice", account.account());
        assertEquals(OtpAlgorithm.SHA1, account.algorithm());
        assertEquals(6, account.digits());
        assertEquals(30L, account.period());
        assertEquals(OtpType.TOTP, account.type());
    }

    @Test
    void parsesHotpWithCounter()
    {
        TwoFactorAccount account = OtpAuthUriParser.parse(
                "otpauth://hotp/Acme:alice?secret=" + SECRET + "&counter=42").get(0);

        assertEquals(OtpType.HOTP, account.type());
        assertEquals(42L, account.counter());
    }

    @Test
    void handlesPercentEncodedLabelAndLowercaseScheme()
    {
        TwoFactorAccount account = OtpAuthUriParser.parse(
                "OTPAUTH://TOTP/Acme%3Aalice%20smith?secret=" + SECRET).get(0);

        assertEquals("Acme", account.issuer());
        assertEquals("alice smith", account.account());
    }

    @Test
    void issuerParameterWinsOverLabel()
    {
        TwoFactorAccount account = OtpAuthUriParser.parse(
                "otpauth://totp/OldName:alice?secret=" + SECRET + "&issuer=NewName").get(0);

        assertEquals("NewName", account.issuer());
        assertEquals("alice", account.account());
    }

    @Test
    void normalisesLowercaseSecret()
    {
        TwoFactorAccount account = OtpAuthUriParser.parse(
                "otpauth://totp/alice?secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq").get(0);

        assertEquals(SECRET, account.secret());
    }

    @Test
    void rejectsMissingOrInvalidSecrets()
    {
        assertThrows(IllegalArgumentException.class, () -> OtpAuthUriParser.parse("otpauth://totp/alice"));
        assertThrows(IllegalArgumentException.class,
                () -> OtpAuthUriParser.parse("otpauth://totp/alice?secret=not-base32!"));
        assertThrows(IllegalArgumentException.class,
                () -> OtpAuthUriParser.parse("otpauth://steam/alice?secret=" + SECRET));
    }

    @Test
    void rejectsUnsupportedAlgorithmAndBadDigits()
    {
        assertThrows(IllegalArgumentException.class,
                () -> OtpAuthUriParser.parse("otpauth://totp/alice?secret=" + SECRET + "&algorithm=MD6"));
        assertThrows(IllegalArgumentException.class,
                () -> OtpAuthUriParser.parse("otpauth://totp/alice?secret=" + SECRET + "&digits=99"));
        assertThrows(IllegalArgumentException.class,
                () -> OtpAuthUriParser.parse("otpauth://totp/alice?secret=" + SECRET + "&period=0"));
    }

    @Test
    void findsUrisInFreeFormText()
    {
        String text = "Scan this: <img src=\"qr.png\"> or use "
                + "otpauth://totp/Acme:alice?secret=" + SECRET + "&issuer=Acme, thanks!";

        List<String> uris = OtpAuthUriParser.findUris(text);
        assertEquals(1, uris.size());
        assertTrue(uris.get(0).endsWith("issuer=Acme"));
        assertFalse(uris.get(0).endsWith(","));
    }

    @Test
    void parsesMultipleUrisFromText()
    {
        String text = "otpauth://totp/A:alice?secret=" + SECRET
                + "\notpauth://totp/B:bob?secret=" + SECRET;

        List<TwoFactorAccount> accounts = OtpAuthUriParser.parseAll(text);
        assertEquals(2, accounts.size());
        assertEquals("A", accounts.get(0).issuer());
        assertEquals("B", accounts.get(1).issuer());
    }

    @Test
    void detectsOtpAuthUris()
    {
        assertTrue(OtpAuthUriParser.looksLikeOtpAuthUri("otpauth://totp/x?secret=" + SECRET));
        assertFalse(OtpAuthUriParser.looksLikeOtpAuthUri("https://example.com"));
        assertFalse(OtpAuthUriParser.looksLikeOtpAuthUri(null));
    }

    @Test
    void parsesBareSecretOnlyWhenPlausible()
    {
        TwoFactorAccount bare = OtpAuthUriParser.parseBareSecret(SECRET);
        assertNotNull(bare);
        assertEquals(SECRET, bare.secret());

        assertNull(OtpAuthUriParser.parseBareSecret("short"));
        assertNull(OtpAuthUriParser.parseBareSecret("this is not a secret at all!!"));
        assertNull(OtpAuthUriParser.parseBareSecret("http://example.com/abcdefghijklmnop"));
    }

    @Test
    void roundTripsThroughUriSerialisation()
    {
        TwoFactorAccount original = OtpAuthUriParser.parse(
                "otpauth://totp/Acme:alice@example.com?secret=" + SECRET
                        + "&issuer=Acme&algorithm=SHA512&digits=7&period=45").get(0);

        TwoFactorAccount reparsed = OtpAuthUriParser.parse(original.toUri()).get(0);

        assertEquals(original.issuer(), reparsed.issuer());
        assertEquals(original.account(), reparsed.account());
        assertEquals(original.secret(), reparsed.secret());
        assertEquals(original.algorithm(), reparsed.algorithm());
        assertEquals(original.digits(), reparsed.digits());
        assertEquals(original.period(), reparsed.period());
    }

    @Test
    void generatesStableCodesThroughAccount()
    {
        TwoFactorAccount account = OtpAuthUriParser.parse(
                "otpauth://totp/alice?secret=" + SECRET + "&digits=8").get(0);

        // Known RFC 6238 vector: t=59 with this secret is 94287082.
        assertEquals("94287082", account.currentCode(59L));
    }
}
