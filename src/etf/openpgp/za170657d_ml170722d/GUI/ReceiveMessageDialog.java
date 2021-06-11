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
		setBounds(100, 100, 594, 331);
		getContentPane().setLayout(null);
		contentPanel.setBounds(0, 0, 576, 249);
		contentPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		getContentPane().add(contentPanel);
		contentPanel.setLayout(null);
		
		JLabel selectedFileLabel = new JLabel("Selected File :");
		selectedFileLabel.setFont(new Font("Tahoma", Font.BOLD, 15));
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
		
		JLabel lblNewLabel = new JLabel("Choose .pgp file  :");
		lblNewLabel.setFont(new Font("Tahoma", Font.BOLD, 16));
		lblNewLabel.setBounds(18, 38, 150, 33);
		contentPanel.add(lblNewLabel);
		
		
		contentPanel.add(selectedFileLabel);
		
		JButton btnNewButton_1 = new JButton("DECRYPT");
		btnNewButton_1.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
	
				//Decryptor.dectyprFile(selectedFile.getAbsolutePath(),outputFilePath);
				System.out.println("Apsolutni : " + selectedFile.getAbsolutePath() + " Neki drugi : " + new File("").getAbsolutePath());
				//Decryptor.dectyprFile(inputFilePath, outputFilePath);
				
				
			}
		});
		btnNewButton_1.setBackground(Color.MAGENTA);
		btnNewButton_1.setForeground(Color.CYAN);
		btnNewButton_1.setFont(new Font("Tahoma", Font.BOLD, 16));
		btnNewButton_1.setBounds(210, 106, 135, 50);
		contentPanel.add(btnNewButton_1);
		{
			JPanel buttonPane = new JPanel();
			buttonPane.setBounds(0, 249, 576, 35);
			buttonPane.setLayout(new FlowLayout(FlowLayout.RIGHT));
			getContentPane().add(buttonPane);
			{
				JButton okButton = new JButton("OK");
				okButton.setActionCommand("OK");
				buttonPane.add(okButton);
				getRootPane().setDefaultButton(okButton);
			}
			{
				JButton cancelButton = new JButton("Cancel");
				cancelButton.setActionCommand("Cancel");
				buttonPane.add(cancelButton);
			}
		}
	}
}
