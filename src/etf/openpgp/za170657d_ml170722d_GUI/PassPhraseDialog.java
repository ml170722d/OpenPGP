package etf.openpgp.za170657d_ml170722d_GUI;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.border.EmptyBorder;
import java.awt.Font;
import java.awt.Toolkit;
import javax.swing.JLabel;
import javax.swing.JTextField;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.SwingConstants;

public class PassPhraseDialog extends JDialog {

	private final JPanel contentPanel = new JPanel();
	private JTextField PasswordTextField;
	private JTextField RepeatTextField;
	
	private String passphrase_password;
	
	
	public String getPassphrase_password() {
		return passphrase_password;
	}

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		try {
			PassPhraseDialog dialog = new PassPhraseDialog();
			dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
			dialog.setVisible(true);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Create the dialog.
	 */
	public PassPhraseDialog() {
		setIconImage(Toolkit.getDefaultToolkit().getImage(PassPhraseDialog.class.getResource("/javax/swing/plaf/metal/icons/ocean/collapsed.gif")));
		setFont(new Font("Dialog", Font.BOLD, 15));
		setTitle("Passphrase Generator");
		setResizable(false);
		setBounds(100, 100, 493, 300);
		getContentPane().setLayout(new BorderLayout());
		contentPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		getContentPane().add(contentPanel, BorderLayout.CENTER);
		contentPanel.setLayout(null);
		{
			JLabel lblPleaseEnterYou = new JLabel("Please enter the passphrase to protect you new key");
			lblPleaseEnterYou.setFont(new Font("Tahoma", Font.BOLD, 16));
			lblPleaseEnterYou.setBounds(28, 27, 432, 52);
			contentPanel.add(lblPleaseEnterYou);
		}
		{
			JLabel PasswordLabel = new JLabel("Password :");
			PasswordLabel.setFont(new Font("Tahoma", Font.PLAIN, 15));
			PasswordLabel.setBounds(60, 92, 77, 16);
			contentPanel.add(PasswordLabel);
		}
		{
			JLabel RepeatPasswordLabel = new JLabel("Repeat Password :");
			RepeatPasswordLabel.setFont(new Font("Tahoma", Font.PLAIN, 15));
			RepeatPasswordLabel.setBounds(38, 149, 132, 16);
			contentPanel.add(RepeatPasswordLabel);
		}
		{
			PasswordTextField = new JPasswordField();
			PasswordTextField.setBounds(169, 92, 179, 22);
			contentPanel.add(PasswordTextField);
			PasswordTextField.setColumns(10);
		}
		{
			RepeatTextField = new JPasswordField();
			RepeatTextField.setBounds(169, 147, 179, 22);
			contentPanel.add(RepeatTextField);
			RepeatTextField.setColumns(10);
		}
		
		JLabel lblErrorMsg = new JLabel("");
		lblErrorMsg.setHorizontalAlignment(SwingConstants.CENTER);
		lblErrorMsg.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblErrorMsg.setBounds(91, 190, 257, 16);
		contentPanel.add(lblErrorMsg);
		{
			JPanel buttonPane = new JPanel();
			buttonPane.setLayout(new FlowLayout(FlowLayout.RIGHT));
			getContentPane().add(buttonPane, BorderLayout.SOUTH);
			{
				JButton okButton = new JButton("OK");
				okButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						String temp_password = PasswordTextField.getText();
						String temp_repeat = RepeatTextField.getText();
						
						if(temp_password.equals("") || temp_repeat.equals("")) {
							lblErrorMsg.setText("Please enter valid data!");
							lblErrorMsg.setForeground(Color.RED);
							return;
						}
						if(!temp_password.equals(temp_repeat)) {
							lblErrorMsg.setText("Passwords do not match!");
							lblErrorMsg.setForeground(Color.RED);
							return;
						}
						
						passphrase_password = temp_password;
						dispose();
					}
				});
				okButton.setActionCommand("OK");
				buttonPane.add(okButton);
				getRootPane().setDefaultButton(okButton);
			}
			{
				JButton cancelButton = new JButton("Cancel");
				cancelButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						dispose();
					}
				});
				cancelButton.setActionCommand("Cancel");
				buttonPane.add(cancelButton);
			}
		}
	}
}
