package twofactor;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * RFC 4226 (HOTP) and RFC 6238 (TOTP) test vectors.
 */
class OtpCodeGeneratorTest
{
    private static final byte[] HOTP_SECRET = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);

    private static final byte[] SHA256_SECRET =
            "12345678901234567890123456789012".getBytes(StandardCharsets.US_ASCII);

    private static final byte[] SHA512_SECRET =
            "1234567890123456789012345678901234567890123456789012345678901234".getBytes(StandardCharsets.US_ASCII);

    @Test
    void matchesRfc4226HotpVectors()
    {
        String[] expected = {
                "755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489"
        };

        for (int counter = 0; counter < expected.length; counter++)
        {
            assertEquals(expected[counter],
                    OtpCodeGenerator.hotp(HOTP_SECRET, OtpAlgorithm.SHA1, 6, counter),
                    "counter " + counter);
        }
    }

    @Test
    void matchesRfc6238TotpSha1Vectors()
    {
        assertEquals("94287082", OtpCodeGenerator.totp(HOTP_SECRET, OtpAlgorithm.SHA1, 8, 30, 59L));
        assertEquals("07081804", OtpCodeGenerator.totp(HOTP_SECRET, OtpAlgorithm.SHA1, 8, 30, 1111111109L));
        assertEquals("14050471", OtpCodeGenerator.totp(HOTP_SECRET, OtpAlgorithm.SHA1, 8, 30, 1111111111L));
        assertEquals("89005924", OtpCodeGenerator.totp(HOTP_SECRET, OtpAlgorithm.SHA1, 8, 30, 1234567890L));
        assertEquals("69279037", OtpCodeGenerator.totp(HOTP_SECRET, OtpAlgorithm.SHA1, 8, 30, 2000000000L));
        assertEquals("65353130", OtpCodeGenerator.totp(HOTP_SECRET, OtpAlgorithm.SHA1, 8, 30, 20000000000L));
    }

    @Test
    void matchesRfc6238TotpSha256Vectors()
    {
        assertEquals("46119246", OtpCodeGenerator.totp(SHA256_SECRET, OtpAlgorithm.SHA256, 8, 30, 59L));
        assertEquals("68084774", OtpCodeGenerator.totp(SHA256_SECRET, OtpAlgorithm.SHA256, 8, 30, 1111111109L));
        assertEquals("67062674", OtpCodeGenerator.totp(SHA256_SECRET, OtpAlgorithm.SHA256, 8, 30, 1111111111L));
        assertEquals("91819424", OtpCodeGenerator.totp(SHA256_SECRET, OtpAlgorithm.SHA256, 8, 30, 1234567890L));
        assertEquals("90698825", OtpCodeGenerator.totp(SHA256_SECRET, OtpAlgorithm.SHA256, 8, 30, 2000000000L));
        assertEquals("77737706", OtpCodeGenerator.totp(SHA256_SECRET, OtpAlgorithm.SHA256, 8, 30, 20000000000L));
    }

    @Test
    void matchesRfc6238TotpSha512Vectors()
    {
        assertEquals("90693936", OtpCodeGenerator.totp(SHA512_SECRET, OtpAlgorithm.SHA512, 8, 30, 59L));
        assertEquals("25091201", OtpCodeGenerator.totp(SHA512_SECRET, OtpAlgorithm.SHA512, 8, 30, 1111111109L));
        assertEquals("99943326", OtpCodeGenerator.totp(SHA512_SECRET, OtpAlgorithm.SHA512, 8, 30, 1111111111L));
        assertEquals("93441116", OtpCodeGenerator.totp(SHA512_SECRET, OtpAlgorithm.SHA512, 8, 30, 1234567890L));
        assertEquals("38618901", OtpCodeGenerator.totp(SHA512_SECRET, OtpAlgorithm.SHA512, 8, 30, 2000000000L));
        assertEquals("47863826", OtpCodeGenerator.totp(SHA512_SECRET, OtpAlgorithm.SHA512, 8, 30, 20000000000L));
    }

    @Test
    void computesSecondsRemaining()
    {
        assertEquals(30L, OtpCodeGenerator.secondsRemaining(30, 0L));
        assertEquals(1L, OtpCodeGenerator.secondsRemaining(30, 29L));
        assertEquals(30L, OtpCodeGenerator.secondsRemaining(30, 30L));
        assertEquals(20L, OtpCodeGenerator.secondsRemaining(30, 100L));
        assertEquals(60L, OtpCodeGenerator.secondsRemaining(60, 0L));
    }

    @Test
    void rejectsInvalidConfiguration()
    {
        assertThrows(IllegalArgumentException.class,
                () -> OtpCodeGenerator.totp(HOTP_SECRET, OtpAlgorithm.SHA1, 6, 0, 59L));
        assertThrows(IllegalArgumentException.class,
                () -> OtpCodeGenerator.hotp(HOTP_SECRET, OtpAlgorithm.SHA1, 0, 1L));
        assertThrows(IllegalArgumentException.class,
                () -> OtpCodeGenerator.hotp(HOTP_SECRET, OtpAlgorithm.SHA1, 11, 1L));
        assertThrows(IllegalArgumentException.class,
                () -> OtpCodeGenerator.hotp(new byte[0], OtpAlgorithm.SHA1, 6, 1L));
    }
}
