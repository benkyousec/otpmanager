package twofactor.ui;

import twofactor.OtpType;
import twofactor.TwoFactorAccount;

import javax.swing.JProgressBar;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;

/**
 * Renderers for the {@code Code} and {@code Valid for} columns.
 */
public final class AccountRenderers
{
    private static final Color EXPIRING = new Color(0xE5, 0x39, 0x35);
    private static final Color HEALTHY = new Color(0x43, 0xA0, 0x47);

    private AccountRenderers()
    {
    }

    public static final class CodeRenderer extends DefaultTableCellRenderer
    {
        private final Font monospaced;

        public CodeRenderer(Font baseFont)
        {
            this.monospaced = new Font(Font.MONOSPACED, Font.BOLD, baseFont == null ? 13 : baseFont.getSize() + 1);
            setHorizontalAlignment(CENTER);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column)
        {
            Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            setFont(monospaced);

            if (!isSelected)
            {
                setForeground(EXPIRING);
                TwoFactorAccount account = accountAt(table, row);

                if (account != null)
                {
                    long remaining = account.secondsRemaining(System.currentTimeMillis() / 1000L);

                    if (account.type() == OtpType.HOTP || remaining > 5)
                    {
                        setForeground(table.getForeground());
                    }
                }
            }

            return component;
        }
    }

    public static final class RemainingRenderer extends JProgressBar implements TableCellRenderer
    {
        public RemainingRenderer()
        {
            super(0, 30);
            setStringPainted(true);
            setBorderPainted(false);
            setFont(getFont().deriveFont(Font.PLAIN, Math.max(10f, getFont().getSize2D() - 1f)));
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column)
        {
            TwoFactorAccount account = accountAt(table, row);

            if (account == null || account.type() == OtpType.HOTP || value == null)
            {
                setValue(0);
                setMaximum(1);
                setString(account != null && account.type() == OtpType.HOTP ? "counter" : "\u2013");
                setForeground(isSelected ? table.getSelectionForeground() : table.getForeground());
                return this;
            }

            int remaining = (Integer) value;
            int period = (int) Math.max(1L, account.period());
            setMaximum(period);
            setValue(remaining);
            setString(remaining + "s");

            if (remaining <= 5)
            {
                setForeground(EXPIRING);
            }
            else
            {
                setForeground(HEALTHY);
            }

            return this;
        }
    }

    private static TwoFactorAccount accountAt(JTable table, int viewRow)
    {
        if (table == null || table.getModel() == null)
        {
            return null;
        }

        int modelRow = table.convertRowIndexToModel(viewRow);

        if (table.getModel() instanceof AccountTableModel model)
        {
            return model.accountAt(modelRow);
        }

        return null;
    }
}
