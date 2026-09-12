package twofactor.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import twofactor.AccountStore;
import twofactor.OtpAuthUriParser;
import twofactor.OtpType;
import twofactor.QrDecoder;
import twofactor.TwoFactorAccount;

import javax.imageio.ImageIO;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.regex.Pattern;

/**
 * The main suite tab: a live-updating grid of registered accounts.
 */
public final class TwoFactorTab extends JPanel
{
    private final MontoyaApi api;
    private final AccountStore store;
    private final ExecutorService worker;
    private final TransferActions transferActions;

    private final AccountTableModel model = new AccountTableModel();
    private final JTable table = new JTable(model);
    private final TableRowSorter<AccountTableModel> sorter = new TableRowSorter<>(model);
    private final JTextField filterField = new JTextField(16);
    private final JLabel statusLabel = new JLabel();
    private final Timer refreshTimer;

    private volatile boolean disposed;

    public TwoFactorTab(MontoyaApi api, AccountStore store, ExecutorService worker)
    {
        super(new BorderLayout(0, 6));
        this.api = api;
        this.store = store;
        this.worker = worker;

        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        configureTable();
        add(buildToolbar(), BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);
        add(buildFooter(), BorderLayout.SOUTH);

        transferActions = new TransferActions(api, store, worker, this);

        store.addChangeListener(() ->
        {
            if (disposed)
            {
                return;
            }

            if (SwingUtilities.isEventDispatchThread())
            {
                refreshFromStore();
            }
            else
            {
                SwingUtilities.invokeLater(this::refreshFromStore);
            }
        });

        refreshFromStore();

        refreshTimer = new Timer(1000, e -> model.refreshValues());
        refreshTimer.setInitialDelay(0);
        refreshTimer.start();

        api.userInterface().applyThemeToComponent(this);
    }

    /**
     * Presents parsed accounts to the user for confirmation and, if approved,
     * registers them. Must be called on the Swing event dispatch thread.
     */
    public void offerAccounts(List<TwoFactorAccount> accounts, String source, boolean alwaysConfirm)
    {
        if (accounts == null || accounts.isEmpty())
        {
            UiUtils.showInfo(this, "No 2FA accounts were found in " + source + ".");
            return;
        }

        boolean confirm = alwaysConfirm || accounts.size() > 1;

        if (confirm && !AccountPreviewDialog.confirm(this, accounts, source))
        {
            setStatus("Registration cancelled.");
            return;
        }

        AccountStore.MergeResult result = store.merge(accounts);

        StringBuilder message = new StringBuilder();
        message.append("Added ").append(result.added()).append(' ')
                .append(UiUtils.plural(result.added(), "account", "accounts")).append('.');

        if (result.updated() > 0)
        {
            message.append(" Advanced ").append(result.updated()).append(" HOTP counter")
                    .append(result.updated() == 1 ? "" : "s").append('.');
        }

        if (result.skipped() > 0)
        {
            message.append(" Skipped ").append(result.skipped()).append(" duplicate")
                    .append(result.skipped() == 1 ? "" : "s").append('.');
        }

        setStatus(message.toString());
    }

    public void dispose()
    {
        disposed = true;

        if (refreshTimer != null)
        {
            refreshTimer.stop();
        }
    }

    private void configureTable()
    {
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setRowHeight(24);
        table.setFillsViewportHeight(true);
        table.setRowSorter(sorter);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);

        Font displayFont = api.userInterface().currentDisplayFont();

        if (displayFont != null)
        {
            table.setFont(displayFont);
        }

        TableColumnModel columns = table.getColumnModel();
        columns.getColumn(AccountTableModel.COLUMN_SERVICE).setPreferredWidth(180);
        columns.getColumn(AccountTableModel.COLUMN_ACCOUNT).setPreferredWidth(200);
        columns.getColumn(AccountTableModel.COLUMN_TYPE).setPreferredWidth(60);
        columns.getColumn(AccountTableModel.COLUMN_CODE).setPreferredWidth(110);
        columns.getColumn(AccountTableModel.COLUMN_REMAINING).setPreferredWidth(90);
        columns.getColumn(AccountTableModel.COLUMN_CONFIG).setPreferredWidth(190);

        columns.getColumn(AccountTableModel.COLUMN_CODE)
                .setCellRenderer(new AccountRenderers.CodeRenderer(displayFont));
        columns.getColumn(AccountTableModel.COLUMN_REMAINING)
                .setCellRenderer(new AccountRenderers.RemainingRenderer());

        table.addMouseListener(new MouseAdapter()
        {
            @Override
            public void mousePressed(MouseEvent e)
            {
                selectRowForPopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e)
            {
                selectRowForPopup(e);
            }

            @Override
            public void mouseClicked(MouseEvent e)
            {
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e))
                {
                    copySelectedCode();
                }
            }
        });

        JPopupMenu popup = new JPopupMenu();
        popup.add(menuItem("Copy code", this::copySelectedCode));
        popup.add(menuItem("Copy otpauth:// URI", this::copySelectedUri));
        popup.addSeparator();
        popup.add(menuItem("Increment HOTP counter", this::incrementSelectedCounter));
        popup.add(menuItem("Edit account\u2026", this::editSelected));
        popup.addSeparator();
        popup.add(menuItem("Remove account", this::removeSelected));
        table.setComponentPopupMenu(popup);

        table.getInputMap(JTable.WHEN_FOCUSED)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_C, java.awt.Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx()), "copyCode");
        table.getActionMap().put("copyCode", new javax.swing.AbstractAction()
        {
            @Override
            public void actionPerformed(ActionEvent e)
            {
                copySelectedCode();
            }
        });
    }

    private JPanel buildToolbar()
    {
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));

        JButton addButton = new JButton("Add \u25be");
        JPopupMenu addMenu = new JPopupMenu();
        addMenu.add(menuItem("From otpauth:// URL\u2026", this::addFromUri));
        addMenu.add(menuItem("From QR code image file\u2026", this::addFromQrFile));
        addMenu.add(menuItem("From clipboard image", this::addFromClipboard));
        addButton.addActionListener(e -> addMenu.show(addButton, 0, addButton.getHeight()));

        JButton copyButton = new JButton("Copy code");
        copyButton.addActionListener(e -> copySelectedCode());

        JButton copyUriButton = new JButton("Copy URI");
        copyUriButton.addActionListener(e -> copySelectedUri());

        JButton editButton = new JButton("Edit\u2026");
        editButton.addActionListener(e -> editSelected());

        JButton removeButton = new JButton("Remove");
        removeButton.addActionListener(e -> removeSelected());

        JButton clearButton = new JButton("Clear all");
        clearButton.addActionListener(e -> clearAll());

        JButton importButton = new JButton("Import\u2026");
        importButton.setToolTipText("Import accounts from a shared export file");
        importButton.addActionListener(e -> transferActions.importAccounts());

        JButton exportButton = new JButton("Export\u2026");
        exportButton.setToolTipText("Export accounts to share with teammates");
        exportButton.addActionListener(e -> transferActions.export());

        toolbar.add(addButton);
        toolbar.add(copyButton);
        toolbar.add(copyUriButton);
        toolbar.add(editButton);
        toolbar.add(removeButton);
        toolbar.add(clearButton);
        toolbar.add(Box.createHorizontalStrut(12));
        toolbar.add(importButton);
        toolbar.add(exportButton);
        toolbar.add(Box.createHorizontalStrut(12));
        toolbar.add(new JLabel("Filter:"));
        toolbar.add(filterField);

        filterField.getDocument().addDocumentListener(new DocumentListener()
        {
            @Override
            public void insertUpdate(DocumentEvent e)
            {
                applyFilter();
            }

            @Override
            public void removeUpdate(DocumentEvent e)
            {
                applyFilter();
            }

            @Override
            public void changedUpdate(DocumentEvent e)
            {
                applyFilter();
            }
        });

        return toolbar;
    }

    private JPanel buildFooter()
    {
        JPanel footer = new JPanel(new BorderLayout(8, 0));

        JCheckBox remember = new JCheckBox("Remember secrets in the project file (unencrypted)",
                store.isPersistenceEnabled());

        remember.addActionListener(e ->
        {
            store.setPersistenceEnabled(remember.isSelected());
            setStatus(remember.isSelected()
                    ? "Secrets will be saved in the current project file."
                    : "Secrets are kept in memory only and will be lost when the project is closed.");
        });

        footer.add(remember, BorderLayout.WEST);
        footer.add(statusLabel, BorderLayout.CENTER);
        return footer;
    }

    private void refreshFromStore()
    {
        List<String> selectedIds = new ArrayList<>();

        for (TwoFactorAccount account : selectedAccounts())
        {
            selectedIds.add(account.id());
        }

        model.setAccounts(store.accounts());

        if (!selectedIds.isEmpty())
        {
            ListSelectionModel selection = table.getSelectionModel();
            selection.clearSelection();

            for (int modelRow = 0; modelRow < model.getRowCount(); modelRow++)
            {
                TwoFactorAccount account = model.accountAt(modelRow);

                if (account != null && selectedIds.contains(account.id()))
                {
                    int viewRow = table.convertRowIndexToView(modelRow);
                    selection.addSelectionInterval(viewRow, viewRow);
                }
            }
        }

        updateCountStatus();
    }

    private void updateCountStatus()
    {
        int count = store.size();
        setStatus("Registered " + count + ' ' + UiUtils.plural(count, "account", "accounts") + '.');
    }

    void setStatus(String message)
    {
        statusLabel.setText(message == null ? "" : message);
    }

    private void applyFilter()
    {
        String text = filterField.getText();

        if (text == null || text.isBlank())
        {
            sorter.setRowFilter(null);
            return;
        }

        sorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(text.trim())));
    }

    /**
     * Selects the row under the pointer before the (automatically shown)
     * component popup menu appears.
     */
    private void selectRowForPopup(MouseEvent e)
    {
        if (!e.isPopupTrigger())
        {
            return;
        }

        int row = table.rowAtPoint(e.getPoint());

        if (row >= 0 && !table.isRowSelected(row))
        {
            table.setRowSelectionInterval(row, row);
        }
    }

    private List<TwoFactorAccount> selectedAccounts()
    {
        List<TwoFactorAccount> selected = new ArrayList<>();

        for (int viewRow : table.getSelectedRows())
        {
            TwoFactorAccount account = model.accountAt(table.convertRowIndexToModel(viewRow));

            if (account != null)
            {
                selected.add(account);
            }
        }

        return selected;
    }

    private void copySelectedCode()
    {
        List<TwoFactorAccount> selected = selectedAccounts();

        if (selected.isEmpty())
        {
            UiUtils.showInfo(this, "Select an account first.");
            return;
        }

        long now = System.currentTimeMillis() / 1000L;
        StringBuilder codes = new StringBuilder();

        for (TwoFactorAccount account : selected)
        {
            if (codes.length() > 0)
            {
                codes.append(System.lineSeparator());
            }

            codes.append(account.currentCode(now));
        }

        if (UiUtils.copyToClipboard(codes.toString()))
        {
            setStatus("Copied " + selected.size() + ' ' + UiUtils.plural(selected.size(), "code", "codes")
                    + " to the clipboard (expires in "
                    + selected.get(0).secondsRemaining(now) + "s).");
        }
        else
        {
            UiUtils.showError(this, "Could not access the system clipboard.");
        }
    }

    private void copySelectedUri()
    {
        List<TwoFactorAccount> selected = selectedAccounts();

        if (selected.isEmpty())
        {
            UiUtils.showInfo(this, "Select an account first.");
            return;
        }

        StringBuilder uris = new StringBuilder();

        for (TwoFactorAccount account : selected)
        {
            if (uris.length() > 0)
            {
                uris.append(System.lineSeparator());
            }

            uris.append(account.toUri());
        }

        if (UiUtils.copyToClipboard(uris.toString()))
        {
            UiUtils.showWarning(this, "The otpauth:// URI contains the shared secret in plaintext "
                    + "and has been copied to the clipboard.");
        }
    }

    private void incrementSelectedCounter()
    {
        List<TwoFactorAccount> selected = selectedAccounts();
        boolean changed = false;

        for (TwoFactorAccount account : selected)
        {
            if (account.type() == OtpType.HOTP)
            {
                account.incrementCounter();
                store.accountUpdated(account);
                changed = true;
            }
        }

        if (changed)
        {
            model.refreshValues();
            setStatus("Incremented HOTP counter.");
        }
        else
        {
            UiUtils.showInfo(this, "The selected account(s) are TOTP, which does not use a counter.");
        }
    }

    private void editSelected()
    {
        List<TwoFactorAccount> selected = selectedAccounts();

        if (selected.size() != 1)
        {
            UiUtils.showInfo(this, "Select exactly one account to edit.");
            return;
        }

        if (AccountEditorDialog.edit(this, selected.get(0)))
        {
            store.accountUpdated(selected.get(0));
            model.refreshValues();
            setStatus("Updated " + selected.get(0).displayName() + '.');
        }
    }

    private void removeSelected()
    {
        List<TwoFactorAccount> selected = selectedAccounts();

        if (selected.isEmpty())
        {
            UiUtils.showInfo(this, "Select an account first.");
            return;
        }

        String message = selected.size() == 1
                ? "Remove " + selected.get(0).displayName() + "?"
                : "Remove " + selected.size() + " accounts?";

        int choice = JOptionPane.showConfirmDialog(this, message, "Remove 2FA account",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);

        if (choice != JOptionPane.OK_OPTION)
        {
            return;
        }

        for (TwoFactorAccount account : selected)
        {
            store.remove(account);
        }

        setStatus("Removed " + selected.size() + ' ' + UiUtils.plural(selected.size(), "account", "accounts") + '.');
    }

    private void clearAll()
    {
        if (store.size() == 0)
        {
            return;
        }

        int choice = JOptionPane.showConfirmDialog(this,
                "Remove all " + store.size() + " registered accounts?",
                "Clear 2FA accounts", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);

        if (choice == JOptionPane.OK_OPTION)
        {
            store.clear();
            setStatus("All accounts removed.");
        }
    }

    private void addFromUri()
    {
        JTextArea input = new JTextArea(8, 48);
        input.setLineWrap(true);
        input.setWrapStyleWord(true);

        while (true)
        {
            int choice = JOptionPane.showConfirmDialog(this,
                    wrapWithLabel("Paste one or more otpauth:// URIs (one per line):", new JScrollPane(input)),
                    "Add from otpauth:// URL", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

            if (choice != JOptionPane.OK_OPTION)
            {
                return;
            }

            try
            {
                List<TwoFactorAccount> accounts = OtpAuthUriParser.parseAll(input.getText());
                offerAccounts(accounts, "the supplied URI", false);
                return;
            }
            catch (IllegalArgumentException e)
            {
                UiUtils.showError(this, e.getMessage());
            }
        }
    }

    private void addFromQrFile()
    {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select a QR code image");
        chooser.setFileFilter(new FileNameExtensionFilter("Images (PNG, JPEG, GIF, BMP)", "png", "jpg", "jpeg", "gif", "bmp"));

        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION)
        {
            return;
        }

        File file = chooser.getSelectedFile();

        if (file == null)
        {
            return;
        }

        setStatus("Decoding " + file.getName() + "\u2026");

        worker.submit(() ->
        {
            try
            {
                BufferedImage image = ImageIO.read(file);
                handleDecodedImage(image, file.getName());
            }
            catch (IOException e)
            {
                SwingUtilities.invokeLater(() -> UiUtils.showError(this, "Could not read the image: " + e.getMessage()));
            }
        });
    }

    private void addFromClipboard()
    {
        BufferedImage image = UiUtils.readImageFromClipboard();

        if (image == null)
        {
            UiUtils.showInfo(this, "The clipboard does not contain an image. Copy a QR code first.");
            return;
        }

        setStatus("Decoding clipboard image\u2026");
        worker.submit(() -> handleDecodedImage(image, "the clipboard image"));
    }

    /**
     * Runs on the worker thread.
     */
    private void handleDecodedImage(BufferedImage image, String source)
    {
        List<String> decoded = image == null ? List.of() : QrDecoder.decode(image);

        SwingUtilities.invokeLater(() ->
        {
            if (disposed)
            {
                return;
            }

            if (decoded.isEmpty())
            {
                UiUtils.showError(this, "No QR code could be decoded from " + source + '.');
                setStatus("No QR code found.");
                return;
            }

            List<TwoFactorAccount> accounts = new ArrayList<>();
            List<String> failures = new ArrayList<>();

            for (String text : decoded)
            {
                try
                {
                    accounts.addAll(OtpAuthUriParser.parse(text.trim()));
                }
                catch (IllegalArgumentException e)
                {
                    TwoFactorAccount bare = OtpAuthUriParser.parseBareSecret(text.trim());

                    if (bare != null)
                    {
                        accounts.add(bare);
                    }
                    else
                    {
                        failures.add(e.getMessage());
                    }
                }
            }

            if (accounts.isEmpty())
            {
                UiUtils.showError(this, "The QR code did not contain provisioning data"
                        + (failures.isEmpty() ? "." : ": " + String.join("; ", failures)));
                setStatus("No 2FA data in QR code.");
                return;
            }

            offerAccounts(accounts, source, true);
        });
    }

    /**
     * Entry point used by the context menu provider (already on the EDT).
     */
    public void offerFromResponses(List<HttpRequestResponse> requestResponses)
    {
        worker.submit(() ->
        {
            twofactor.ResponseScanner.ScanResult result = twofactor.ResponseScanner.scan(requestResponses);

            SwingUtilities.invokeLater(() ->
            {
                if (disposed)
                {
                    return;
                }

                for (String note : result.notes())
                {
                    api.logging().logToOutput("[2FA Code Generator] " + note);
                }

                if (result.isEmpty())
                {
                    UiUtils.showInfo(this, "No QR codes or otpauth:// URIs were found in the selected response(s).");
                    setStatus("Nothing found in selected response(s).");
                    return;
                }

                offerAccounts(result.accounts(), "the selected response(s)", true);
            });
        });
    }

    private static JPanel wrapWithLabel(String label, JScrollPane scrollPane)
    {
        JPanel panel = new JPanel(new BorderLayout(0, 6));
        panel.add(new JLabel(label), BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);
        panel.setPreferredSize(new Dimension(520, 200));
        return panel;
    }

    private static JMenuItem menuItem(String text, Runnable action)
    {
        JMenuItem item = new JMenuItem(text);
        item.addActionListener(e -> action.run());
        return item;
    }
}
