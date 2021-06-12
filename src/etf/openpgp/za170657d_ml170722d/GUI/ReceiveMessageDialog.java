package etf.openpgp.za170657d_ml170722d.GUI;

import java.awt.BorderLayout;
import java.awt.FlowLayout;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import etf.openpgp.za170657d_ml170722d.securityV2.Decryptor;
import etf.openpgp.za170657d_ml170722d.securityV2.Decryptor.Info;
import etf.openpgp.za170657d_ml170722d.securityV2.KeyChain;
import etf.openpgp.za170657d_ml170722d.securityV2.KeyManager;

import java.awt.Toolkit;
import javax.swing.JLabel;
import java.awt.Font;
import java.awt.event.ActionListener;
import java.io.File;
import java.awt.event.ActionEvent;
import java.awt.Color;
import javax.swing.border.LineBorder;
import javax.swing.table.DefaultTableModel;

public class ReceiveMessageDialog extends JDialog {

	private final JPanel contentPanel = new JPanel();
	
	private File selectedFile;

	/**
	 * Launch the application.
	 */


	/**
	 * Create the dialog.
	 */
	public ReceiveMessageDialog() {
		setIconImage(Toolkit.getDefaultToolkit().getImage(ReceiveMessageDialog.class.getResource("/com/sun/java/swing/plaf/windows/icons/Computer.gif")));
		setTitle("Receive Message");
		setBounds(100, 100, 598, 451);
		getContentPane().setLayout(null);
		contentPanel.setBounds(0, 0, 576, 366);
		contentPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		getContentPane().add(contentPanel);
		contentPanel.setLayout(null);
		
		JLabel lblEncrypt = new JLabel("Encryption status : unknown");
		lblEncrypt.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblEncrypt.setBounds(18, 200, 275, 33);
		contentPanel.add(lblEncrypt);
		
		JLabel lblSignature = new JLabel("Signature status : unknown");
		lblSignature.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblSignature.setBounds(18, 250, 275, 33);
		contentPanel.add(lblSignature);
		
		JLabel selectedFileLabel = new JLabel("Selected File :");
		selectedFileLabel.setFont(new Font("Tahoma", Font.BOLD, 16));
		selectedFileLabel.setBounds(334, 38, 242, 33);
		
		JButton btnSaveResult = new JButton("SAVE");
		btnSaveResult.setEnabled(false);
		btnSaveResult.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				final JFileChooser fileChooser = new JFileChooser(new File("").getAbsoluteFile());
				fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
				int result = fileChooser.showOpenDialog(contentPanel);
				if (result == JFileChooser.APPROVE_OPTION) {
					
					System.out.println(fileChooser.getSelectedFile().getAbsolutePath());
	
					try {
						Decryptor.dectyprFile(selectedFile.getAbsolutePath(),fileChooser.getSelectedFile().getAbsolutePath()+ '\\');
					} catch (Exception e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
					
				}
					
			}
		});
		
		JLabel lblUserStatus = new JLabel("User status : unknown");
		lblUserStatus.setBounds(18, 300, 263, 33);
		contentPanel.add(lblUserStatus);
		lblUserStatus.setFont(new Font("Tahoma", Font.PLAIN, 15));
		
		JButton btnDecrpyt = new JButton("DECRYPT");
		btnDecrpyt.setEnabled(false);
		btnDecrpyt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
	
				System.out.println("Apsolutni : " + selectedFile.getAbsolutePath() + " Neki drugi : " + new File("").getAbsolutePath());
				
				Info info_item = null;
				
				try {
					info_item = Decryptor.dectyprFile(selectedFile.getAbsolutePath(), new File("").getAbsolutePath());
					
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();		
				}
				
				if(info_item == null) {
					lblEncrypt.setText("Encryption status : error with the file");
					lblSignature.setText("Signature status : error with the file");
					lblUserStatus.setText("User status :  error with the file");
					return;
					
				}
				
				if(info_item.isEncrypted()) {
					lblEncrypt.setText("Encryption status : message encrypted");
				}
				else {
					lblEncrypt.setText("Encryption status : message not encrypted");
				}
				
				if(info_item.isSigned()) {
					lblSignature.setText("Signature status : message signed");
				}
				else {
					lblSignature.setText("Signature status : message not signed");
				}
				
				//lblUserStatus.setText("User status : " + KeyChain.getKeyRing(info_item.getId()).getUserId());
				String arrSplit[] = KeyChain.getKeyRing(info_item.getId()).getUserId().split("<");
				lblUserStatus.setText("User status : " + arrSplit[0].toString() + " - " + arrSplit[1].substring(0, arrSplit[1].length() - 1));
				btnSaveResult.setEnabled(true);
			}
		});
		btnDecrpyt.setBackground(Color.MAGENTA);
		btnDecrpyt.setForeground(Color.CYAN);
		btnDecrpyt.setFont(new Font("Tahoma", Font.BOLD, 16));
		btnDecrpyt.setBounds(71, 114, 135, 50);
		contentPanel.add(btnDecrpyt);
		
		
		JButton btnNewButton = new JButton("SELECT FILE");
		btnNewButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				final JFileChooser fileChooser = new JFileChooser(new File("").getAbsoluteFile());
				int result = fileChooser.showOpenDialog(contentPanel);
				if(result == JFileChooser.APPROVE_OPTION) {
					selectedFile = fileChooser.getSelectedFile();
					selectedFileLabel.setText("Selected File : " + selectedFile.getName());
					btnDecrpyt.setEnabled(true);
				}
			}
		});
		btnNewButton.setFont(new Font("Tahoma", Font.BOLD, 15));
		btnNewButton.setBounds(180, 38, 142, 33);
		contentPanel.add(btnNewButton);
		
		JLabel lblNewLabel = new JLabel("Choose .pgp file");
		lblNewLabel.setFont(new Font("Tahoma", Font.BOLD, 16));
		lblNewLabel.setBounds(18, 38, 150, 33);
		contentPanel.add(lblNewLabel);
		
		
		contentPanel.add(selectedFileLabel);
		btnSaveResult.setBackground(Color.RED);
		btnSaveResult.setForeground(Color.CYAN);
		btnSaveResult.setFont(new Font("Tahoma", Font.BOLD, 16));
		btnSaveResult.setBounds(355, 114, 135, 50);
		contentPanel.add(btnSaveResult);
		{
			JPanel buttonPane = new JPanel();
			buttonPane.setBounds(0, 369, 576, 35);
			buttonPane.setLayout(new FlowLayout(FlowLayout.RIGHT));
			getContentPane().add(buttonPane);
			{
				JButton okButton = new JButton("OK");
				okButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						dispose();
					}
				});
				okButton.setFont(new Font("Tahoma", Font.PLAIN, 15));
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
				cancelButton.setFont(new Font("Tahoma", Font.PLAIN, 15));
				cancelButton.setActionCommand("Cancel");
				buttonPane.add(cancelButton);
			}
		}
	}
}
