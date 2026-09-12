package twofactor.ui;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import java.awt.Component;
import java.awt.GridLayout;
import java.util.Arrays;

/**
 * Dialogs for choosing export options and supplying passphrases.
 */
public final class TransferDialogs
{
    public enum ExportFormat
    {
        ENCRYPTED,
        PLAINTEXT_JSON,
        URI_LIST
    }

    public record ExportChoice(ExportFormat format, char[] passphrase)
    {
    }

    private static final int MIN_PASSPHRASE_LENGTH = 8;

    private TransferDialogs()
    {
    }

    /**
     * @return the chosen export options, or {@code null} if cancelled
     */
    public static ExportChoice showExportOptions(Component parent, int accountCount)
    {
        JRadioButton encrypted = new JRadioButton("Encrypted (recommended)", true);
        JRadioButton plaintextJson = new JRadioButton("Plaintext JSON");
        JRadioButton uriList = new JRadioButton("Plaintext otpauth:// URI list (.txt)");

        ButtonGroup group = new ButtonGroup();
        group.add(encrypted);
        group.add(plaintextJson);
        group.add(uriList);

        JPasswordField passphrase = new JPasswordField(22);
        JPasswordField confirmation = new JPasswordField(22);

        JPanel passphrasePanel = new JPanel(new GridLayout(2, 2, 6, 4));
        passphrasePanel.add(new JLabel("Passphrase:"));
        passphrasePanel.add(passphrase);
        passphrasePanel.add(new JLabel("Confirm:"));
        passphrasePanel.add(confirmation);

        JLabel warning = new JLabel();

        Runnable sync = () ->
        {
            boolean isEncrypted = encrypted.isSelected();
            passphrase.setEnabled(isEncrypted);
            confirmation.setEnabled(isEncrypted);
            warning.setText(isEncrypted
                    ? "Anyone with the passphrase can generate your codes."
                    : "Warning: the secrets will be written in plaintext and are readable by anyone.");
        };

        encrypted.addActionListener(e -> sync.run());
        plaintextJson.addActionListener(e -> sync.run());
        uriList.addActionListener(e -> sync.run());
        sync.run();

        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        panel.add(new JLabel("Export " + accountCount + " account(s) as:"));
        panel.add(encrypted);
        panel.add(plaintextJson);
        panel.add(uriList);
        panel.add(passphrasePanel);
        panel.add(warning);

        while (true)
        {
            int choice = JOptionPane.showConfirmDialog(parent, panel, "Export 2FA accounts",
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

            if (choice != JOptionPane.OK_OPTION)
            {
                Arrays.fill(passphrase.getPassword(), '\0');
                Arrays.fill(confirmation.getPassword(), '\0');
                return null;
            }

            if (plaintextJson.isSelected())
            {
                return new ExportChoice(ExportFormat.PLAINTEXT_JSON, null);
            }

            if (uriList.isSelected())
            {
                return new ExportChoice(ExportFormat.URI_LIST, null);
            }

            char[] first = passphrase.getPassword();
            char[] second = confirmation.getPassword();

            if (first.length < MIN_PASSPHRASE_LENGTH)
            {
                clear(first, second);
                UiUtils.showError(parent, "Use a passphrase of at least " + MIN_PASSPHRASE_LENGTH + " characters.");
                continue;
            }

            if (!Arrays.equals(first, second))
            {
                clear(first, second);
                UiUtils.showError(parent, "The passphrases do not match.");
                continue;
            }

            Arrays.fill(second, '\0');
            return new ExportChoice(ExportFormat.ENCRYPTED, first);
        }
    }

    /**
     * Prompts for a passphrase.
     *
     * @param confirm when true, asks for the passphrase twice
     * @return the entered passphrase, or {@code null} if cancelled
     */
    public static char[] promptPassphrase(Component parent, String message, boolean confirm)
    {
        JPanel panel = new JPanel(new GridLayout(confirm ? 2 : 1, 2, 6, 4));
        JLabel label = new JLabel(message);
        JPasswordField field = new JPasswordField(22);

        panel.add(label);
        panel.add(field);

        JPasswordField confirmation = new JPasswordField(22);

        if (confirm)
        {
            panel.add(new JLabel("Confirm:"));
            panel.add(confirmation);
        }

        while (true)
        {
            int choice = JOptionPane.showConfirmDialog(parent, panel, "Passphrase",
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

            if (choice != JOptionPane.OK_OPTION)
            {
                return null;
            }

            char[] first = field.getPassword();

            if (first.length == 0)
            {
                UiUtils.showError(parent, "Enter a passphrase.");
                continue;
            }

            if (!confirm)
            {
                return first;
            }

            char[] second = confirmation.getPassword();

            if (!Arrays.equals(first, second))
            {
                clear(first, second);
                UiUtils.showError(parent, "The passphrases do not match.");
                continue;
            }

            Arrays.fill(second, '\0');
            return first;
        }
    }

    private static void clear(char[] first, char[] second)
    {
        Arrays.fill(first, '\0');
        Arrays.fill(second, '\0');
    }
}
