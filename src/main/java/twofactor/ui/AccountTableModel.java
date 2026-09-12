package twofactor.ui;

import twofactor.OtpType;
import twofactor.TwoFactorAccount;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Table model backing the registered-accounts grid. Code and remaining-time
 * values are computed on demand so refreshing them once a second is cheap.
 */
public final class AccountTableModel extends AbstractTableModel
{
    public static final int COLUMN_SERVICE = 0;
    public static final int COLUMN_ACCOUNT = 1;
    public static final int COLUMN_TYPE = 2;
    public static final int COLUMN_CODE = 3;
    public static final int COLUMN_REMAINING = 4;
    public static final int COLUMN_CONFIG = 5;

    private static final String[] COLUMNS = {"Service", "Account", "Type", "Code", "Valid for", "Config"};

    private List<TwoFactorAccount> rows = new ArrayList<>();

    public void setAccounts(List<TwoFactorAccount> accounts)
    {
        rows = new ArrayList<>(accounts);
        fireTableDataChanged();
    }

    public TwoFactorAccount accountAt(int modelRow)
    {
        if (modelRow < 0 || modelRow >= rows.size())
        {
            return null;
        }

        return rows.get(modelRow);
    }

    public void refreshValues()
    {
        if (!rows.isEmpty())
        {
            fireTableRowsUpdated(0, rows.size() - 1);
        }
    }

    @Override
    public int getRowCount()
    {
        return rows.size();
    }

    @Override
    public int getColumnCount()
    {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column)
    {
        return COLUMNS[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        return columnIndex == COLUMN_REMAINING ? Integer.class : String.class;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex)
    {
        return false;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        TwoFactorAccount account = accountAt(rowIndex);

        if (account == null)
        {
            return "";
        }

        long now = System.currentTimeMillis() / 1000L;

        return switch (columnIndex)
        {
            case COLUMN_SERVICE -> account.issuer();
            case COLUMN_ACCOUNT -> account.account();
            case COLUMN_TYPE -> account.type().name();
            case COLUMN_CODE -> account.currentCode(now);
            case COLUMN_REMAINING -> account.type() == OtpType.TOTP
                    ? (int) account.secondsRemaining(now)
                    : null;
            case COLUMN_CONFIG -> account.configSummary();
            default -> "";
        };
    }

    public long periodFor(int modelRow)
    {
        TwoFactorAccount account = accountAt(modelRow);
        return account == null ? 30L : account.period();
    }
}
