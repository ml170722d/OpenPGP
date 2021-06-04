package etf.openpgp.za170657d_ml170722d.GUI;

import java.awt.BorderLayout;
import java.awt.FlowLayout;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import etf.openpgp.za170657d_ml170722d.securityV2.KeyChain;
import etf.openpgp.za170657d_ml170722d.securityV2.KeyManager;
import etf.openpgp.za170657d_ml170722d.securityV2.KeyRing.KeyRingTags;

import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.security.KeyPair;

import javax.swing.JLabel;
import java.awt.Font;

import javax.swing.AbstractButton;
import javax.swing.ButtonGroup;
import javax.swing.JRadioButton;

public class ExportDialog extends JDialog {

	private final JPanel contentPanel = new JPanel();

	private String selectedKeyType;
	

	/**
	 * Create the dialog.
	 */
	public ExportDialog(long keyId, int keyIndex) {
		setIconImage(Toolkit.getDefaultToolkit().getImage(ExportDialog.class.getResource("/javax/swing/plaf/metal/icons/ocean/info.png")));
		setTitle("Export Key");
		setResizable(false);
		setModal(true);
		setBounds(100, 100, 450, 300);
		getContentPane().setLayout(new BorderLayout());
		contentPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		getContentPane().add(contentPanel, BorderLayout.CENTER);
		contentPanel.setLayout(null);
		{
			JLabel lblNewLabel = new JLabel("You are about to export key :");
			lblNewLabel.setFont(new Font("Tahoma", Font.PLAIN, 17));
			lblNewLabel.setBounds(22, 49, 232, 26);
			contentPanel.add(lblNewLabel);
		}
		{
			JLabel lblKeyID = new JLabel("");
			lblKeyID.setFont(new Font("Tahoma", Font.PLAIN, 15));
			lblKeyID.setBounds(250, 56, 175, 16);
			contentPanel.add(lblKeyID);
			lblKeyID.setText(Long.toString(keyId));
		}
		
		JRadioButton PublicKeyButton = new JRadioButton("Public Key");
		PublicKeyButton.setFont(new Font("Tahoma", Font.PLAIN, 15));
		PublicKeyButton.setBounds(298, 128, 127, 25);
		contentPanel.add(PublicKeyButton);
		
		JRadioButton PrivateKeyButton = new JRadioButton("Private Key");
		PrivateKeyButton.setFont(new Font("Tahoma", Font.PLAIN, 15));
		PrivateKeyButton.setBounds(156, 128, 127, 25);
		contentPanel.add(PrivateKeyButton);
		
		ButtonGroup buttonGroup = new ButtonGroup();
		buttonGroup.add(PrivateKeyButton);
		buttonGroup.add(PublicKeyButton);
		
		ActionListener buttonGroupListener = new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				// TODO Auto-generated method stub
				AbstractButton button = (AbstractButton) e.getSource();
				System.out.println("Selected " + button.getText());
				selectedKeyType = button.getText();
				
			}
		};
		
		/*if(KeyChain.getKeyRing(keyId).hasPrivateKey())
			PublicKeyButton.setSelected(true);
		else if (KeyChain.getKeyRing(keyId).hasPrivateKey())
			*/
			
	
		PublicKeyButton.addActionListener(buttonGroupListener);
		PrivateKeyButton.addActionListener(buttonGroupListener);
		
		JLabel lblChooseKey = new JLabel("Choose key :");
		lblChooseKey.setFont(new Font("Tahoma", Font.PLAIN, 17));
		lblChooseKey.setBounds(22, 117, 127, 44);
		contentPanel.add(lblChooseKey);
		{
			JPanel buttonPane = new JPanel();
			buttonPane.setLayout(new FlowLayout(FlowLayout.RIGHT));
			getContentPane().add(buttonPane, BorderLayout.SOUTH);
			{
				JButton okButton = new JButton("OK");
				okButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						if(selectedKeyType.contains("Public")) {
							try {
								KeyManager.exportKey(keyId, KeyRingTags.PUBLIC, Long.toString(keyId)+ "_PUBLIC.asc");
							} catch (Exception e1) {
								// TODO Auto-generated catch block
								e1.printStackTrace();
							}			
						}
						else {
							try {
								KeyManager.exportKey(keyId, KeyRingTags.PRIVATE, Long.toString(keyId)+ "_PRIVATE.asc");
							} catch (Exception e1) {
								// TODO Auto-generated catch block
								e1.printStackTrace();
							}
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
