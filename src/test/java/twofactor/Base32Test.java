package twofactor;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Base32Test
{
    @Test
    void decodesRfc4648Vector()
    {
        byte[] decoded = Base32.decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assertEquals("12345678901234567890", new String(decoded));
    }

    @Test
    void decodeIsForgivingOfFormatting()
    {
        byte[] expected = "12345678901234567890".getBytes();

        assertArrayEquals(expected, Base32.decode("gezdgnbvgy3tqojqgezdgnbvgy3tqojq"));
        assertArrayEquals(expected, Base32.decode("GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ"));
        assertArrayEquals(expected, Base32.decode("GEZD-GNBV-GY3T-QOJQ-GEZD-GNBV-GY3T-QOJQ"));
        assertArrayEquals(expected, Base32.decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ===="));
    }

    @Test
    void rejectsInvalidCharacters()
    {
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> Base32.decode("GEZD1NBV"));

        assertEquals(true, error.getMessage().contains("Invalid Base32"));
    }

    @Test
    void rejectsEmptySecrets()
    {
        assertThrows(IllegalArgumentException.class, () -> Base32.decode("   "));
    }

    @Test
    void encodeRoundTrips()
    {
        byte[] data = new byte[]{0x00, 0x01, 0x02, 0x7F, (byte) 0x80, (byte) 0xFF};
        byte[] roundTripped = Base32.decode(Base32.encode(data));
        assertArrayEquals(data, roundTripped);
    }

    @Test
    void encodesKnownVector()
    {
        assertEquals("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                Base32.encode("12345678901234567890".getBytes()));
    }
}
