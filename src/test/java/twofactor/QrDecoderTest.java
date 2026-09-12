package twofactor;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class QrDecoderTest
{
    private static final String SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    private static final String URI = "otpauth://totp/Acme:alice?secret=" + SECRET + "&issuer=Acme";

    @Test
    void decodesGeneratedQrCode() throws Exception
    {
        BufferedImage image = renderQr(URI, 300, 300);

        List<String> decoded = QrDecoder.decode(image);

        assertEquals(List.of(URI), decoded);
    }

    @Test
    void decodesQrCodeFromPngBytes() throws Exception
    {
        byte[] png = toPng(renderQr(URI, 240, 240));

        List<String> decoded = QrDecoder.decodeImageBytes(png);

        assertEquals(List.of(URI), decoded);
    }

    @Test
    void decodesRotatedQrCode() throws Exception
    {
        BufferedImage rotated = rotate90(renderQr(URI, 260, 260));

        List<String> decoded = QrDecoder.decode(rotated);

        assertEquals(List.of(URI), decoded);
    }

    @Test
    void returnsEmptyForNonQrImages()
    {
        BufferedImage blank = new BufferedImage(200, 200, BufferedImage.TYPE_INT_RGB);

        assertTrue(QrDecoder.decode(blank).isEmpty());
        assertTrue(QrDecoder.decodeImageBytes(new byte[0]).isEmpty());
        assertTrue(QrDecoder.decodeImageBytes("not an image".getBytes()).isEmpty());
        assertTrue(QrDecoder.decode(null).isEmpty());
    }

    @Test
    void extractsQrCodesFromDataUris() throws Exception
    {
        String base64 = Base64.getEncoder().encodeToString(toPng(renderQr(URI, 260, 260)));
        String html = "<html><body><img src=\"data:image/png;base64," + base64 + "\"></body></html>";

        List<String> decoded = QrDecoder.decodeDataUriImages(html);

        assertEquals(List.of(URI), decoded);
    }

    @Test
    void recognisesImageMagicNumbers()
    {
        byte[] png = new byte[]{(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
        byte[] jpeg = new byte[]{(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0, 0, 0, 0, 0};

        assertTrue(QrDecoder.looksLikeImage(png));
        assertTrue(QrDecoder.looksLikeImage(jpeg));
        assertFalse(QrDecoder.looksLikeImage("{\"hello\":\"world\"}".getBytes()));
        assertFalse(QrDecoder.looksLikeImage(null));
    }

    private static BufferedImage renderQr(String text, int width, int height) throws WriterException
    {
        BitMatrix matrix = new QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, width, height);
        BufferedImage image = new BufferedImage(matrix.getWidth(), matrix.getHeight(), BufferedImage.TYPE_INT_RGB);

        for (int y = 0; y < matrix.getHeight(); y++)
        {
            for (int x = 0; x < matrix.getWidth(); x++)
            {
                image.setRGB(x, y, matrix.get(x, y) ? 0xFF000000 : 0xFFFFFFFF);
            }
        }

        return image;
    }

    private static byte[] toPng(BufferedImage image) throws IOException
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(image, "png", out);
        return out.toByteArray();
    }

    private static BufferedImage rotate90(BufferedImage source)
    {
        int width = source.getWidth();
        int height = source.getHeight();
        BufferedImage rotated = new BufferedImage(height, width, BufferedImage.TYPE_INT_RGB);

        Graphics2D graphics = rotated.createGraphics();
        graphics.translate(height, 0);
        graphics.rotate(Math.PI / 2);
        graphics.drawImage(source, 0, 0, null);
        graphics.dispose();
        return rotated;
    }
}
