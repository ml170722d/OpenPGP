package etf.openpgp.za170657d_ml170722d.GUI;

import java.awt.BorderLayout;

import etf.openpgp.za170657d_ml170722d.security.error.AlreadyInUse;
import etf.openpgp.za170657d_ml170722d.securityV2.KeyManager;

import java.awt.Color;
import java.awt.FlowLayout;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.border.EmptyBorder;

import org.bouncycastle.openpgp.PGPException;
import java.awt.Font;
import java.awt.Toolkit;
import javax.swing.JLabel;
import javax.swing.JTextField;
import java.awt.event.ActionListener;
import java.security.NoSuchAlgorithmException;
import java.awt.event.ActionEvent;
import javax.swing.SwingConstants;

public class PassPhraseDialog extends JDialog {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private final JPanel contentPanel = new JPanel();
	private JTextField PasswordTextField;
	private JTextField RepeatTextField;
	private MainMenuWindow mainWindow;

	private String passphrase_password;
	private String userID;
	private int keySize;

	public String getPassphrase_password() {
		return passphrase_password;
	}

	/**
	 * Launch the application.
	 */

	/**
	 * Create the dialog.
	 */
	public PassPhraseDialog(MainMenuWindow mainWindow, String userID, int keySize) {

		this.userID = userID;
		this.keySize = keySize;
		this.mainWindow = mainWindow;

		setIconImage(Toolkit.getDefaultToolkit()
				.getImage(PassPhraseDialog.class.getResource("/javax/swing/plaf/metal/icons/ocean/collapsed.gif")));
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

						if (temp_password.equals("") || temp_repeat.equals("")) {
							lblErrorMsg.setText("Please enter valid data!");
							lblErrorMsg.setForeground(Color.RED);
							return;
						}
						if (!temp_password.equals(temp_repeat)) {
							lblErrorMsg.setText("Passwords do not match!");
							lblErrorMsg.setForeground(Color.RED);
							return;
						}

						passphrase_password = temp_password;
						// From this part of code you have passphrase password,email and keysize!!!

						/*
						 * try { KeyManager km = KeyManager.getInstance(); switch (keySize) { case 1024:
						 * km.generateRSAKeyPairEncryption(passphrase_password.toCharArray(), email,
						 * RSAUtil.KeySize._1024b, RSAUtil.KeySize._1024b); break; case 2048:
						 * km.generateRSAKeyPairEncryption(passphrase_password.toCharArray(), email,
						 * RSAUtil.KeySize._2048b, RSAUtil.KeySize._2048b); break; case 4096:
						 * km.generateRSAKeyPairEncryption(passphrase_password.toCharArray(), email,
						 * RSAUtil.KeySize._4096b, RSAUtil.KeySize._4096b); break;
						 * 
						 * default: break; }
						 */

						try {
							KeyManager.generateRSAKeyPair(passphrase_password.toCharArray(), userID, keySize);
						} catch (NoSuchAlgorithmException | PGPException | AlreadyInUse e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						}

						mainWindow.addKeyPair();
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
