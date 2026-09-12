package twofactor;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Test helper that renders real QR codes with ZXing's encoder so the decoder
 * and scanner can be exercised end to end.
 */
final class TestQrCodes
{
    private TestQrCodes()
    {
    }

    static BufferedImage render(String text, int size)
    {
        try
        {
            BitMatrix matrix = new QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size);
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
        catch (WriterException e)
        {
            throw new IllegalStateException("Could not render QR code", e);
        }
    }

    static byte[] png(String text, int size)
    {
        try
        {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ImageIO.write(render(text, size), "png", out);
            return out.toByteArray();
        }
        catch (IOException e)
        {
            throw new IllegalStateException("Could not encode PNG", e);
        }
    }
}
