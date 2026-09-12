package twofactor;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Builds Google Authenticator migration payloads for tests using a hand-rolled
 * protobuf encoder, so the parser is exercised against real wire bytes.
 */
final class TestMigrationPayloads
{
    private TestMigrationPayloads()
    {
    }

    /**
     * Wraps one or more encoded {@code OtpParameters} blocks in a migration URI.
     */
    static String uri(byte[]... parameterBlocks)
    {
        ByteArrayOutputStream payload = new ByteArrayOutputStream();

        for (byte[] block : parameterBlocks)
        {
            writeTag(payload, 1, 2);
            writeVarint(payload, block.length);
            payload.writeBytes(block);
        }

        String base64 = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.toByteArray());
        return "otpauth-migration://offline?data=" + base64;
    }

    static byte[] parameters(byte[] secret, String name, String issuer,
                             int algorithm, int digits, int type, long counter)
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeBytesField(out, 1, secret);
        writeStringField(out, 2, name);
        writeStringField(out, 3, issuer);
        writeVarintField(out, 4, algorithm);
        writeVarintField(out, 5, digits);
        writeVarintField(out, 6, type);
        writeVarintField(out, 7, counter);
        return out.toByteArray();
    }

    static String singleAccountUri(String issuer, String account, String secret)
    {
        return uri(parameters(secret.getBytes(StandardCharsets.US_ASCII),
                issuer + ":" + account, issuer, 1, 1, 2, 0L));
    }

    private static void writeBytesField(ByteArrayOutputStream out, int field, byte[] value)
    {
        writeTag(out, field, 2);
        writeVarint(out, value.length);
        out.writeBytes(value);
    }

    private static void writeStringField(ByteArrayOutputStream out, int field, String value)
    {
        writeBytesField(out, field, value.getBytes(StandardCharsets.UTF_8));
    }

    private static void writeVarintField(ByteArrayOutputStream out, int field, long value)
    {
        writeTag(out, field, 0);
        writeVarint(out, value);
    }

    private static void writeTag(ByteArrayOutputStream out, int field, int wireType)
    {
        writeVarint(out, ((long) field << 3) | wireType);
    }

    private static void writeVarint(ByteArrayOutputStream out, long value)
    {
        long remaining = value;

        while ((remaining & ~0x7FL) != 0)
        {
            out.write((int) ((remaining & 0x7F) | 0x80));
            remaining >>>= 7;
        }

        out.write((int) remaining);
    }
}
