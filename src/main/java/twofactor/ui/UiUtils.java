package twofactor.ui;

import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Graphics2D;
import java.awt.Image;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.image.BufferedImage;

/**
 * Small UI helpers shared by the tab and the dialogs.
 */
public final class UiUtils
{
    private UiUtils()
    {
    }

    /**
     * Copies text to the system clipboard, retrying briefly because the
     * clipboard is occasionally locked by another process.
     */
    public static boolean copyToClipboard(String text)
    {
        if (text == null || text.isEmpty())
        {
            return false;
        }

        StringSelection selection = new StringSelection(text);
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();

        for (int attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                clipboard.setContents(selection, selection);
                return true;
            }
            catch (IllegalStateException e)
            {
                try
                {
                    Thread.sleep(50L);
                }
                catch (InterruptedException interrupted)
                {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
        }

        return false;
    }

    /**
     * Returns an image from the system clipboard, or {@code null} when the
     * clipboard does not contain one.
     */
    public static BufferedImage readImageFromClipboard()
    {
        try
        {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();

            if (!clipboard.isDataFlavorAvailable(DataFlavor.imageFlavor))
            {
                return null;
            }

            Object data = clipboard.getData(DataFlavor.imageFlavor);

            if (data instanceof Image image)
            {
                return toBufferedImage(image);
            }
        }
        catch (Exception e)
        {
            return null;
        }

        return null;
    }

    public static BufferedImage toBufferedImage(Image image)
    {
        if (image instanceof BufferedImage buffered)
        {
            return buffered;
        }

        int width = Math.max(1, image.getWidth(null));
        int height = Math.max(1, image.getHeight(null));
        BufferedImage buffered = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);

        Graphics2D graphics = buffered.createGraphics();
        graphics.drawImage(image, 0, 0, null);
        graphics.dispose();
        return buffered;
    }

    /**
     * Masks a secret for display, revealing only enough to recognise it.
     */
    public static String maskSecret(String secret)
    {
        if (secret == null || secret.isEmpty())
        {
            return "";
        }

        if (secret.length() <= 6)
        {
            return "\u2022".repeat(secret.length());
        }

        return secret.substring(0, 2)
                + "\u2022".repeat(Math.min(12, secret.length() - 4))
                + secret.substring(secret.length() - 2);
    }

    public static void showInfo(Component parent, String message)
    {
        JOptionPane.showMessageDialog(parent, message, "2FA Code Generator", JOptionPane.INFORMATION_MESSAGE);
    }

    public static void showError(Component parent, String message)
    {
        JOptionPane.showMessageDialog(parent, message, "2FA Code Generator", JOptionPane.ERROR_MESSAGE);
    }

    public static void showWarning(Component parent, String message)
    {
        JOptionPane.showMessageDialog(parent, message, "2FA Code Generator", JOptionPane.WARNING_MESSAGE);
    }

    public static String plural(int count, String singular, String plural)
    {
        return count == 1 ? singular : plural;
    }

    /**
     * Runs a task on the Swing event dispatch thread, blocking the caller until
     * it completes. Used by background workers that need to show a dialog.
     */
    public static <T> T onEdt(java.util.concurrent.Callable<T> callable)
    {
        if (SwingUtilities.isEventDispatchThread())
        {
            try
            {
                return callable.call();
            }
            catch (RuntimeException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new IllegalStateException(e);
            }
        }

        Object[] result = new Object[1];
        RuntimeException[] failure = new RuntimeException[1];

        try
        {
            SwingUtilities.invokeAndWait(() ->
            {
                try
                {
                    result[0] = callable.call();
                }
                catch (RuntimeException e)
                {
                    failure[0] = e;
                }
                catch (Exception e)
                {
                    failure[0] = new IllegalStateException(e);
                }
            });
        }
        catch (InterruptedException e)
        {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
        catch (java.lang.reflect.InvocationTargetException e)
        {
            throw new IllegalStateException(e);
        }

        if (failure[0] != null)
        {
            throw failure[0];
        }

        @SuppressWarnings("unchecked")
        T typed = (T) result[0];
        return typed;
    }
}
