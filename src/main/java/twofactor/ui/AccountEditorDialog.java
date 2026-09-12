package twofactor.ui;

import twofactor.Base32;
import twofactor.OtpAlgorithm;
import twofactor.OtpCodeGenerator;
import twofactor.OtpType;
import twofactor.TwoFactorAccount;

import javax.swing.BorderFactory;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSpinner;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

/**
 * Add/edit form for a single account. Validation happens before anything is
 * applied, so cancelling never leaves a partially edited account behind.
 */
public final class AccountEditorDialog
{
    private AccountEditorDialog()
    {
    }

    /**
     * @return true when the account was updated
     */
    public static boolean edit(Component parent, TwoFactorAccount account)
    {
        JTextField issuerField = new JTextField(account.issuer(), 24);
        JTextField accountField = new JTextField(account.account(), 24);
        JTextField secretField = new JTextField(account.secret(), 24);

        JComboBox<OtpType> typeBox = new JComboBox<>(new DefaultComboBoxModel<>(OtpType.values()));
        typeBox.setSelectedItem(account.type());

        JComboBox<OtpAlgorithm> algorithmBox = new JComboBox<>(new DefaultComboBoxModel<>(OtpAlgorithm.values()));
        algorithmBox.setSelectedItem(account.algorithm());

        JSpinner digitsSpinner = new JSpinner(new SpinnerNumberModel(
                account.digits(), OtpCodeGenerator.MIN_DIGITS, OtpCodeGenerator.MAX_DIGITS, 1));

        JSpinner periodSpinner = new JSpinner(new SpinnerNumberModel(
                (int) Math.min(Integer.MAX_VALUE, Math.max(1L, account.period())), 1, 86_400, 1));

        JSpinner counterSpinner = new JSpinner(new SpinnerNumberModel(
                Math.min(1_000_000_000L, Math.max(0L, account.counter())), 0L, 1_000_000_000L, 1L));

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        int row = 0;
        addRow(form, row++, "Service / issuer", issuerField);
        addRow(form, row++, "Account", accountField);
        addRow(form, row++, "Secret (Base32)", secretField);
        addRow(form, row++, "Type", typeBox);
        addRow(form, row++, "Algorithm", algorithmBox);
        addRow(form, row++, "Digits", digitsSpinner);
        addRow(form, row++, "Period (seconds, TOTP)", periodSpinner);
        addRow(form, row, "Counter (HOTP)", counterSpinner);

        Runnable syncEnabledState = () ->
        {
            boolean totp = typeBox.getSelectedItem() == OtpType.TOTP;
            periodSpinner.setEnabled(totp);
            counterSpinner.setEnabled(!totp);
        };

        typeBox.addActionListener(e -> syncEnabledState.run());
        syncEnabledState.run();

        while (true)
        {
            int choice = JOptionPane.showConfirmDialog(
                    parent,
                    form,
                    "Edit 2FA account",
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.PLAIN_MESSAGE);

            if (choice != JOptionPane.OK_OPTION)
            {
                return false;
            }

            String secret = Base32.normalize(secretField.getText());

            try
            {
                Base32.decode(secret);
            }
            catch (IllegalArgumentException e)
            {
                UiUtils.showError(parent, "The secret is not valid Base32: " + e.getMessage());
                continue;
            }

            OtpType type = (OtpType) typeBox.getSelectedItem();
            OtpAlgorithm algorithm = (OtpAlgorithm) algorithmBox.getSelectedItem();

            account.setIssuer(issuerField.getText());
            account.setAccount(accountField.getText());
            account.setSecret(secret);
            account.setType(type);
            account.setAlgorithm(algorithm);
            account.setDigits((Integer) digitsSpinner.getValue());
            account.setPeriod(((Number) periodSpinner.getValue()).longValue());
            account.setCounter(((Number) counterSpinner.getValue()).longValue());
            return true;
        }
    }

    private static void addRow(JPanel panel, int row, String label, Component field)
    {
        GridBagConstraints labelConstraints = new GridBagConstraints();
        labelConstraints.gridx = 0;
        labelConstraints.gridy = row;
        labelConstraints.anchor = GridBagConstraints.LINE_END;
        labelConstraints.insets = new Insets(3, 3, 3, 8);

        GridBagConstraints fieldConstraints = new GridBagConstraints();
        fieldConstraints.gridx = 1;
        fieldConstraints.gridy = row;
        fieldConstraints.fill = GridBagConstraints.HORIZONTAL;
        fieldConstraints.weightx = 1.0;
        fieldConstraints.insets = new Insets(3, 0, 3, 3);

        panel.add(new JLabel(label), labelConstraints);
        panel.add(field, fieldConstraints);
    }
}
