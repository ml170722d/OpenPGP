package etf.openpgp.za170657d_ml170722d.GUI;

import java.awt.BorderLayout;
import java.awt.FlowLayout;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import etf.openpgp.za170657d_ml170722d.securityV2.Decryptor;

import java.awt.Toolkit;
import javax.swing.JLabel;
import java.awt.Font;
import java.awt.event.ActionListener;
import java.io.File;
import java.awt.event.ActionEvent;
import java.awt.Color;
import javax.swing.border.LineBorder;

public class ReceiveMessageDialog extends JDialog {

	private final JPanel contentPanel = new JPanel();
	private File selectedFile;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		try {
			ReceiveMessageDialog dialog = new ReceiveMessageDialog();
			dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
			dialog.setVisible(true);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

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
		
		JLabel selectedFileLabel = new JLabel("Selected File :");
		selectedFileLabel.setFont(new Font("Tahoma", Font.BOLD, 16));
		selectedFileLabel.setBounds(334, 38, 242, 33);
		
		
		JButton btnNewButton = new JButton("SELECT FILE");
		btnNewButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				final JFileChooser fileChooser = new JFileChooser(new File("").getAbsoluteFile());
				int result = fileChooser.showOpenDialog(contentPanel);
				if(result == JFileChooser.APPROVE_OPTION) {
					selectedFile = fileChooser.getSelectedFile();
					selectedFileLabel.setText("Selected File : " + selectedFile.getName());
					
				}
			}
		});
		btnNewButton.setFont(new Font("Tahoma", Font.BOLD, 15));
		btnNewButton.setBounds(180, 38, 142, 33);
		contentPanel.add(btnNewButton);
		
		JLabel lblUserStatus = new JLabel("User status : unknown");
		lblUserStatus.setBounds(18, 300, 230, 33);
		contentPanel.add(lblUserStatus);
		lblUserStatus.setFont(new Font("Tahoma", Font.PLAIN, 15));
		
		JLabel lblNewLabel = new JLabel("Choose .pgp file");
		lblNewLabel.setFont(new Font("Tahoma", Font.BOLD, 16));
		lblNewLabel.setBounds(18, 38, 150, 33);
		contentPanel.add(lblNewLabel);
		
		
		contentPanel.add(selectedFileLabel);
		
		JButton btnDecrpyt = new JButton("DECRYPT");
		btnDecrpyt.setEnabled(false);
		btnDecrpyt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
	
				//Decryptor.dectyprFile(selectedFile.getAbsolutePath(),outputFilePath);
				System.out.println("Apsolutni : " + selectedFile.getAbsolutePath() + " Neki drugi : " + new File("").getAbsolutePath());
				//Decryptor.dectyprFile(inputFilePath, outputFilePath);
	
				
			}
		});
		btnDecrpyt.setBackground(Color.MAGENTA);
		btnDecrpyt.setForeground(Color.CYAN);
		btnDecrpyt.setFont(new Font("Tahoma", Font.BOLD, 16));
		btnDecrpyt.setBounds(71, 114, 135, 50);
		contentPanel.add(btnDecrpyt);
		
		JLabel lblEncrypt = new JLabel("Encryption status : unknown");
		lblEncrypt.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblEncrypt.setBounds(18, 200, 230, 33);
		contentPanel.add(lblEncrypt);
		
		JLabel lblSignature = new JLabel("Signature status : unknown");
		lblSignature.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblSignature.setBounds(18, 250, 230, 33);
		contentPanel.add(lblSignature);
		
		JButton btnSaveResult = new JButton("SAVE");
		btnSaveResult.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
			}
		});
		btnSaveResult.setEnabled(false);
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
