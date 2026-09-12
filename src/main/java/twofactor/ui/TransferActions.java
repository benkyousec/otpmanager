package twofactor.ui;

import burp.api.montoya.MontoyaApi;
import twofactor.AccountStore;
import twofactor.AccountTransfer;
import twofactor.DecryptionException;
import twofactor.TwoFactorAccount;

import javax.swing.JFileChooser;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;

/**
 * Import/export workflow: file choosers, background crypto/IO and passphrase
 * prompts. Kept out of {@link TwoFactorTab} to stop that class growing further.
 */
final class TransferActions
{
    private static final long MAX_IMPORT_BYTES = 10L * 1024 * 1024;
    private static final int MAX_PASSPHRASE_ATTEMPTS = 3;
    private static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");

    private final MontoyaApi api;
    private final AccountStore store;
    private final ExecutorService worker;
    private final TwoFactorTab tab;

    TransferActions(MontoyaApi api, AccountStore store, ExecutorService worker, TwoFactorTab tab)
    {
        this.api = api;
        this.store = store;
        this.worker = worker;
        this.tab = tab;
    }

    void export()
    {
        List<TwoFactorAccount> accounts = store.accounts();

        if (accounts.isEmpty())
        {
            UiUtils.showInfo(tab, "There are no registered accounts to export.");
            return;
        }

        TransferDialogs.ExportChoice choice = TransferDialogs.showExportOptions(tab, accounts.size());

        if (choice == null)
        {
            return;
        }

        File file = chooseSaveFile(choice.format());

        if (file == null)
        {
            return;
        }

        tab.setStatus("Exporting " + accounts.size() + " accounts\u2026");

        worker.submit(() ->
        {
            char[] passphrase = choice.passphrase();

            try
            {
                String content = switch (choice.format())
                {
                    case ENCRYPTED -> AccountTransfer.exportJson(accounts, passphrase);
                    case PLAINTEXT_JSON -> AccountTransfer.exportJson(accounts, null);
                    case URI_LIST -> AccountTransfer.exportUris(accounts);
                };

                writeFile(file, content);

                SwingUtilities.invokeLater(() ->
                {
                    tab.setStatus("Exported " + accounts.size() + " accounts to " + file.getName() + '.');

                    if (choice.format() == TransferDialogs.ExportFormat.ENCRYPTED)
                    {
                        UiUtils.showInfo(tab, "Exported " + accounts.size() + " accounts to:\n" + file
                                + "\n\nShare the file and the passphrase separately.");
                    }
                    else
                    {
                        UiUtils.showWarning(tab, "Exported " + accounts.size() + " accounts in plaintext to:\n" + file
                                + "\n\nAnyone who can read this file can generate your codes.");
                    }
                });
            }
            catch (IOException e)
            {
                SwingUtilities.invokeLater(() ->
                {
                    UiUtils.showError(tab, "Export failed: " + e.getMessage());
                    tab.setStatus("Export failed.");
                });
            }
            finally
            {
                Arrays.fill(passphrase == null ? new char[0] : passphrase, '\0');
            }
        });
    }

    void importAccounts()
    {
        File file = chooseOpenFile();

        if (file == null)
        {
            return;
        }

        tab.setStatus("Reading " + file.getName() + "\u2026");

        worker.submit(() ->
        {
            try
            {
                if (file.length() > MAX_IMPORT_BYTES)
                {
                    SwingUtilities.invokeLater(() -> UiUtils.showError(tab,
                            "The file is larger than " + (MAX_IMPORT_BYTES / (1024 * 1024)) + " MB."));
                    return;
                }

                String content = Files.readString(file.toPath(), StandardCharsets.UTF_8);
                AccountTransfer.ImportResult result = readContent(content, file);

                if (result == null)
                {
                    return;
                }

                for (String warning : result.warnings())
                {
                    api.logging().logToOutput("[2FA Code Generator] Import: " + warning);
                }

                SwingUtilities.invokeLater(() ->
                {
                    if (result.encrypted())
                    {
                        tab.setStatus("Decrypted " + result.accounts().size() + " accounts from " + file.getName() + '.');
                    }

                    tab.offerAccounts(result.accounts(), "the imported file " + file.getName(), true);
                });
            }
            catch (IllegalArgumentException e)
            {
                SwingUtilities.invokeLater(() ->
                {
                    UiUtils.showError(tab, "Import failed: " + e.getMessage());
                    tab.setStatus("Import failed.");
                });
            }
            catch (IOException e)
            {
                SwingUtilities.invokeLater(() ->
                {
                    UiUtils.showError(tab, "Could not read the file: " + e.getMessage());
                    tab.setStatus("Import failed.");
                });
            }
        });
    }

    /**
     * Runs on the worker thread. Returns {@code null} when the user cancels.
     */
    private AccountTransfer.ImportResult readContent(String content, File file)
    {
        if (!AccountTransfer.isEncrypted(content))
        {
            return AccountTransfer.importContent(content, null);
        }

        for (int attempt = 1; attempt <= MAX_PASSPHRASE_ATTEMPTS; attempt++)
        {
            int attemptNumber = attempt;
            char[] passphrase = UiUtils.onEdt(() -> TransferDialogs.promptPassphrase(tab,
                    "Enter the passphrase for " + escape(file.getName()) + ":",
                    false));

            if (passphrase == null)
            {
                SwingUtilities.invokeLater(() -> tab.setStatus("Import cancelled."));
                return null;
            }

            try
            {
                return AccountTransfer.importContent(content, passphrase);
            }
            catch (DecryptionException e)
            {
                if (attemptNumber < MAX_PASSPHRASE_ATTEMPTS)
                {
                    UiUtils.onEdt(() ->
                    {
                        UiUtils.showError(tab, "Incorrect passphrase. Please try again.");
                        return null;
                    });
                }
            }
            finally
            {
                Arrays.fill(passphrase, '\0');
            }
        }

        SwingUtilities.invokeLater(() ->
        {
            UiUtils.showError(tab, "Import failed: incorrect passphrase, or the file is corrupted.");
            tab.setStatus("Import failed.");
        });
        return null;
    }

    private File chooseSaveFile(TransferDialogs.ExportFormat format)
    {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export 2FA accounts");

        boolean uriList = format == TransferDialogs.ExportFormat.URI_LIST;
        chooser.setSelectedFile(new File("2fa-accounts-" + LocalDateTime.now().format(TIMESTAMP)
                + (uriList ? ".txt" : ".2fa.json")));

        if (uriList)
        {
            chooser.setFileFilter(new FileNameExtensionFilter("Text files (*.txt)", "txt"));
        }
        else
        {
            chooser.setFileFilter(new FileNameExtensionFilter("2FA export files (*.json, *.2fa)", "json", "2fa"));
        }

        if (chooser.showSaveDialog(tab) != JFileChooser.APPROVE_OPTION)
        {
            return null;
        }

        File file = chooser.getSelectedFile();

        if (file == null)
        {
            return null;
        }

        if (file.getName().indexOf('.') < 0)
        {
            file = new File(file.getParentFile(), file.getName() + (uriList ? ".txt" : ".2fa.json"));
        }

        if (file.exists())
        {
            int overwrite = javax.swing.JOptionPane.showConfirmDialog(tab,
                    "Overwrite " + file.getName() + '?', "Export 2FA accounts",
                    javax.swing.JOptionPane.OK_CANCEL_OPTION, javax.swing.JOptionPane.WARNING_MESSAGE);

            if (overwrite != javax.swing.JOptionPane.OK_OPTION)
            {
                return null;
            }
        }

        return file;
    }

    private File chooseOpenFile()
    {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import 2FA accounts");
        chooser.setFileFilter(new FileNameExtensionFilter(
                "2FA export files (*.json, *.2fa, *.txt)", "json", "2fa", "txt"));

        if (chooser.showOpenDialog(tab) != JFileChooser.APPROVE_OPTION)
        {
            return null;
        }

        return chooser.getSelectedFile();
    }

    private static void writeFile(File file, String content) throws IOException
    {
        Files.writeString(file.toPath(), content, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);

        try
        {
            Files.setPosixFilePermissions(file.toPath(), PosixFilePermissions.fromString("rw-------"));
        }
        catch (UnsupportedOperationException | IOException ignored)
        {
            // Not a POSIX filesystem (e.g. Windows) - best effort only.
        }
    }

    private static String escape(String value)
    {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
