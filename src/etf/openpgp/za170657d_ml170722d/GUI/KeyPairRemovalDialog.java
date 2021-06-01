package etf.openpgp.za170657d_ml170722d.GUI;

import java.awt.BorderLayout;
import java.awt.FlowLayout;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.border.EmptyBorder;

import etf.openpgp.za170657d_ml170722d.security.KeyManager;

import javax.swing.JLabel;
import java.awt.Font;
import java.awt.RenderingHints.Key;

import javax.swing.ImageIcon;
import java.awt.Toolkit;
import javax.swing.JTextField;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class KeyPairRemovalDialog extends JDialog {

	private final JPanel contentPanel = new JPanel();
	private JTextField passwordField;

	public boolean success = false;
	
	public boolean isSuccess() {
		return success;
	}
	
	public void setSuccess(boolean success) {
		this.success = success;
	}

	/**
	 * Create the dialog.
	 */
	public KeyPairRemovalDialog(MainMenuWindow mainWindow, int index) {
		setModal(true);
		setAlwaysOnTop(true);
		setIconImage(Toolkit.getDefaultToolkit().getImage(KeyPairRemovalDialog.class.getResource("/javax/swing/plaf/metal/icons/ocean/collapsed.gif")));
		setTitle("Key Removal");
		setResizable(false);
		setBounds(100, 100, 428, 257);
		getContentPane().setLayout(new BorderLayout());
		contentPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		getContentPane().add(contentPanel, BorderLayout.CENTER);
		contentPanel.setLayout(null);
		
		JLabel lblNewLabel = new JLabel("Enter password for key removal");
		lblNewLabel.setIcon(null);
		lblNewLabel.setFont(new Font("Tahoma", Font.BOLD, 16));
		lblNewLabel.setBounds(69, 40, 297, 33);
		contentPanel.add(lblNewLabel);
		
		JLabel lblNewLabel_1 = new JLabel("Password :");
		lblNewLabel_1.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_1.setBounds(56, 95, 110, 33);
		contentPanel.add(lblNewLabel_1);
		
		passwordField = new JPasswordField();
		passwordField.setFont(new Font("Tahoma", Font.PLAIN, 15));
		passwordField.setBounds(137, 98, 206, 28);
		contentPanel.add(passwordField);
		passwordField.setColumns(10);
		
		JLabel lblError = new JLabel("");
		lblError.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblError.setBounds(110, 147, 233, 27);
		contentPanel.add(lblError);
		{
			JPanel buttonPane = new JPanel();
			buttonPane.setLayout(new FlowLayout(FlowLayout.RIGHT));
			getContentPane().add(buttonPane, BorderLayout.SOUTH);
			{
				JButton okButton = new JButton("OK");
				okButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						
						String password = passwordField.getText();
						
						if(password.equals("")) {
							lblError.setText("Please enter valid password");
							return;
						}
						System.out.println("Password " + password + " Index : " + index);
						boolean status = KeyManager.getInstance().deleteKey(index, password.toCharArray());
						System.out.println("status :" + status);
						if(!status) {
							lblError.setText("Wrong password, removal faild!");
							success = false;
							return;
						}
						else {
							success = true;
							mainWindow.userInfoList = KeyManager.getInstance().getUIUserInfo();
							dispose();
						}
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
