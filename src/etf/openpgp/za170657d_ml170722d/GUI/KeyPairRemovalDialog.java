package etf.openpgp.za170657d_ml170722d.GUI;

import java.awt.BorderLayout;
import java.awt.FlowLayout;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.border.EmptyBorder;

import etf.openpgp.za170657d_ml170722d.security.KeyRing.KeyRingType;
import etf.openpgp.za170657d_ml170722d.securityV2.KeyChain;
import etf.openpgp.za170657d_ml170722d.securityV2.KeyManager;
import etf.openpgp.za170657d_ml170722d.securityV2.KeyRing.KeyRingTags;

import javax.swing.JLabel;
import java.awt.Font;
import java.awt.RenderingHints.Key;

import javax.swing.AbstractButton;
import javax.swing.ButtonGroup;
import javax.swing.ImageIcon;
import java.awt.Toolkit;
import javax.swing.JTextField;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JRadioButton;

public class KeyPairRemovalDialog extends JDialog {

	private final JPanel contentPanel = new JPanel();
	private JTextField passwordField;

	public boolean success = false;
	
	private boolean keyTypePrivate = false;
	private boolean keyTypePublic = false;
	
	public boolean isSuccess() {
		return success;
	}
	
	public void setSuccess(boolean success) {
		this.success = success;
	}

	/**
	 * Create the dialog.
	 */
	public KeyPairRemovalDialog(MainMenuWindow mainWindow, long keyID) {
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
		
		JLabel lblNewLabel = new JLabel("Enter password and choose key type for removal");
		lblNewLabel.setIcon(null);
		lblNewLabel.setFont(new Font("Tahoma", Font.BOLD, 16));
		lblNewLabel.setBounds(12, 13, 410, 33);
		contentPanel.add(lblNewLabel);
		
		JLabel lblNewLabel_1 = new JLabel("Password :");
		lblNewLabel_1.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_1.setBounds(12, 111, 110, 33);
		contentPanel.add(lblNewLabel_1);
		
		passwordField = new JPasswordField();
		passwordField.setEnabled(false);
		passwordField.setFont(new Font("Tahoma", Font.PLAIN, 15));
		passwordField.setBounds(110, 114, 206, 28);
		contentPanel.add(passwordField);
		passwordField.setColumns(10);
		
		JLabel lblError = new JLabel("");
		lblError.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblError.setBounds(110, 147, 233, 27);
		contentPanel.add(lblError);
		
		JLabel lblNewLabel_2 = new JLabel("Key Type :");
		lblNewLabel_2.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblNewLabel_2.setBounds(12, 59, 84, 39);
		contentPanel.add(lblNewLabel_2);
		
		JRadioButton publicKeyRadioButton = new JRadioButton("Public ");
		publicKeyRadioButton.setFont(new Font("Tahoma", Font.PLAIN, 15));
		publicKeyRadioButton.setBounds(103, 67, 69, 25);
		contentPanel.add(publicKeyRadioButton);
		
		JRadioButton privateKeyRadioButton = new JRadioButton("Private");
		privateKeyRadioButton.setFont(new Font("Tahoma", Font.PLAIN, 15));
		privateKeyRadioButton.setBounds(189, 67, 127, 25);
		
		
		ActionListener buttonGroupActionListener = new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				// TODO Auto-generated method stub
				AbstractButton btn = (AbstractButton) e.getSource();
				if(btn.getText().contains("Public")){
					keyTypePublic = true;
					passwordField.setEnabled(false);
				}
				else if (btn.getText().contains("Private")){
					keyTypePrivate = true;
					passwordField.setEnabled(true);
				}
			}
		};
 		
		privateKeyRadioButton.addActionListener(buttonGroupActionListener);
		publicKeyRadioButton.addActionListener(buttonGroupActionListener);
		
		contentPanel.add(privateKeyRadioButton);
		{
			JPanel buttonPane = new JPanel();
			buttonPane.setLayout(new FlowLayout(FlowLayout.RIGHT));
			getContentPane().add(buttonPane, BorderLayout.SOUTH);
			{
				JButton okButton = new JButton("OK");
				okButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						
						String password = passwordField.getText();
					
						if(password.equals("") && keyTypePrivate) {
							lblError.setText("Please enter valid password");
							return;
						}
						
						if(keyTypePublic) {
							try {
								KeyManager.deleteKey(keyID, KeyRingTags.PUBLIC, password.toCharArray());
							} catch (Exception e1) {
								// TODO Auto-generated catch block
								e1.printStackTrace();
							}
							success = true;
						}
						
						
						 if (keyTypePrivate) {
							boolean status = false;;
							try {
								status = KeyManager.deleteKey(keyID, KeyRingTags.PRIVATE, password.toCharArray());
							} catch (Exception e1) {
								// TODO Auto-generated catch block
								e1.printStackTrace();
							}
							if(!status) {
								lblError.setText("Wrong password, removal faild!");
								success = false;
								return;
							}
							else
								success = true;
						}
						
			
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
