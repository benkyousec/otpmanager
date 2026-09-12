package twofactor.ui;

import twofactor.TwoFactorAccount;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.util.List;

/**
 * Confirmation step shown before accounts are registered. This exists because
 * provisioning data can come from an untrusted HTTP response: the user must
 * explicitly approve the accounts, and the secret is masked.
 */
public final class AccountPreviewDialog
{
    private AccountPreviewDialog()
    {
    }

    public static boolean confirm(Component parent, List<TwoFactorAccount> accounts, String source)
    {
        if (accounts == null || accounts.isEmpty())
        {
            return false;
        }

        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        String heading = accounts.size() == 1
                ? "One account was found from " + source + ". Register it?"
                : accounts.size() + " accounts were found from " + source + ". Register them?";

        panel.add(new JLabel(heading), BorderLayout.NORTH);

        JTable table = new JTable(buildModel(accounts));
        table.setRowHeight(Math.max(22, table.getRowHeight()));
        table.setFillsViewportHeight(true);

        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.setPreferredSize(new Dimension(640, Math.min(280, 60 + accounts.size() * 24)));
        panel.add(scrollPane, BorderLayout.CENTER);

        panel.add(new JLabel("Secrets are masked. Review the service and account before registering."),
                BorderLayout.SOUTH);

        int choice = JOptionPane.showConfirmDialog(
                parent,
                panel,
                "Register 2FA accounts",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE);

        return choice == JOptionPane.OK_OPTION;
    }

    private static TableModel buildModel(List<TwoFactorAccount> accounts)
    {
        String[] columns = {"Service", "Account", "Type", "Config", "Secret"};

        return new AbstractTableModel()
        {
            @Override
            public int getRowCount()
            {
                return accounts.size();
            }

            @Override
            public int getColumnCount()
            {
                return columns.length;
            }

            @Override
            public String getColumnName(int column)
            {
                return columns[column];
            }

            @Override
            public Object getValueAt(int rowIndex, int columnIndex)
            {
                TwoFactorAccount account = accounts.get(rowIndex);

                return switch (columnIndex)
                {
                    case 0 -> account.issuer();
                    case 1 -> account.account();
                    case 2 -> account.type().name();
                    case 3 -> account.configSummary();
                    case 4 -> UiUtils.maskSecret(account.secret());
                    default -> "";
                };
            }
        };
    }
}
