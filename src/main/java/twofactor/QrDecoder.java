package twofactor;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.NotFoundException;
import com.google.zxing.RGBLuminanceSource;
import com.google.zxing.Result;
import com.google.zxing.common.HybridBinarizer;

import javax.imageio.ImageIO;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Decodes QR codes from images using ZXing.
 *
 * <p>Decoding is defensive: large images are downscaled and rotation attempts
 * are bounded so that a hostile or oversized image cannot stall the worker
 * thread indefinitely.</p>
 */
public final class QrDecoder
{
    private static final int MAX_PIXELS = 16_000_000;
    private static final int MAX_ROTATION_PIXELS = 4_000_000;
    private static final int MAX_TEXT_URI_LENGTH = 4096;

    private static final Pattern DATA_URI_PATTERN = Pattern.compile(
            "(?i)data:image/(?:png|jpe?g|gif|bmp);base64,([A-Za-z0-9+/=\\s]{16,})");

    private static final int MAX_DATA_URI_IMAGES = 8;
    private static final int MAX_DATA_URI_CHARS = 12_000_000;

    private QrDecoder()
    {
    }

    public static List<String> decode(BufferedImage source)
    {
        if (source == null || source.getWidth() <= 0 || source.getHeight() <= 0)
        {
            return List.of();
        }

        BufferedImage image = downscale(source);
        boolean rotate = (long) image.getWidth() * image.getHeight() <= MAX_ROTATION_PIXELS;
        int attempts = rotate ? 4 : 1;

        BufferedImage current = image;

        for (int i = 0; i < attempts; i++)
        {
            String text = decodeSingle(current);

            if (text != null)
            {
                return List.of(text.trim());
            }

            String invertedText = decodeSingle(invert(current));

            if (invertedText != null)
            {
                return List.of(invertedText.trim());
            }

            if (rotate)
            {
                current = rotate90(current);
            }
        }

        return List.of();
    }

    public static List<String> decodeImageBytes(byte[] bytes)
    {
        if (bytes == null || bytes.length == 0)
        {
            return List.of();
        }

        try
        {
            BufferedImage image = ImageIO.read(new ByteArrayInputStream(bytes));

            if (image == null)
            {
                return List.of();
            }

            return decode(image);
        }
        catch (IOException | RuntimeException e)
        {
            return List.of();
        }
    }

    /**
     * Decodes images embedded in text as {@code data:image/...;base64,...} URIs.
     * Returns the decoded payloads of every QR code found.
     */
    public static List<String> decodeDataUriImages(String text)
    {
        if (text == null || text.isEmpty())
        {
            return List.of();
        }

        Set<String> results = new LinkedHashSet<>();
        Matcher matcher = DATA_URI_PATTERN.matcher(text);
        int processed = 0;

        while (matcher.find() && processed < MAX_DATA_URI_IMAGES)
        {
            String base64 = matcher.group(1).replaceAll("\\s", "");

            if (base64.length() > MAX_DATA_URI_CHARS)
            {
                continue;
            }

            processed++;

            try
            {
                byte[] decoded = java.util.Base64.getDecoder().decode(base64);
                results.addAll(decodeImageBytes(decoded));
            }
            catch (IllegalArgumentException e)
            {
                // Not valid base64 - ignore.
            }
        }

        return new ArrayList<>(results);
    }

    /**
     * True when the payload has a magic number for a raster image format that
     * ZXing can decode.
     */
    public static boolean looksLikeImage(byte[] body)
    {
        if (body == null || body.length < 8)
        {
            return false;
        }

        // PNG
        if ((body[0] & 0xFF) == 0x89 && body[1] == 'P' && body[2] == 'N' && body[3] == 'G')
        {
            return true;
        }

        // JPEG
        if ((body[0] & 0xFF) == 0xFF && (body[1] & 0xFF) == 0xD8 && (body[2] & 0xFF) == 0xFF)
        {
            return true;
        }

        // GIF
        if (body[0] == 'G' && body[1] == 'I' && body[2] == 'F' && body[3] == '8')
        {
            return true;
        }

        // BMP
        return body[0] == 'B' && body[1] == 'M';
    }

    private static String decodeSingle(BufferedImage image)
    {
        try
        {
            int width = image.getWidth();
            int height = image.getHeight();
            int[] pixels = image.getRGB(0, 0, width, height, null, 0, width);

            RGBLuminanceSource source = new RGBLuminanceSource(width, height, pixels);
            BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));

            Map<DecodeHintType, Object> hints = new EnumMap<>(DecodeHintType.class);
            hints.put(DecodeHintType.TRY_HARDER, Boolean.TRUE);
            hints.put(DecodeHintType.POSSIBLE_FORMATS, List.of(BarcodeFormat.QR_CODE));

            Result result = new MultiFormatReader().decode(bitmap, hints);
            String text = result.getText();

            if (text == null)
            {
                return null;
            }

            text = text.replace("\u0000", "").trim();

            if (text.isEmpty() || text.length() > MAX_TEXT_URI_LENGTH * 4)
            {
                return text.isEmpty() ? null : text.substring(0, MAX_TEXT_URI_LENGTH * 4);
            }

            return text;
        }
        catch (NotFoundException | RuntimeException e)
        {
            return null;
        }
    }

    private static BufferedImage downscale(BufferedImage source)
    {
        long pixels = (long) source.getWidth() * source.getHeight();

        if (pixels <= MAX_PIXELS)
        {
            return source;
        }

        double scale = Math.sqrt((double) MAX_PIXELS / pixels);
        int width = Math.max(1, (int) (source.getWidth() * scale));
        int height = Math.max(1, (int) (source.getHeight() * scale));

        BufferedImage scaled = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D graphics = scaled.createGraphics();
        graphics.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
        graphics.drawImage(source, 0, 0, width, height, null);
        graphics.dispose();
        return scaled;
    }

    private static BufferedImage invert(BufferedImage source)
    {
        int width = source.getWidth();
        int height = source.getHeight();
        BufferedImage inverted = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);

        for (int y = 0; y < height; y++)
        {
            for (int x = 0; x < width; x++)
            {
                int argb = source.getRGB(x, y);
                inverted.setRGB(x, y, (~argb) & 0x00FFFFFF);
            }
        }

        return inverted;
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
