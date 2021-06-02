package etf.openpgp.za170657d_ml170722d.GUI;

import java.awt.BorderLayout;
import java.awt.FlowLayout;

import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileSystemView;

import etf.openpgp.za170657d_ml170722d.security.KeyManager;

import java.awt.Toolkit;
import java.util.ArrayList;
import java.util.Iterator;

import javax.swing.JLabel;
import java.awt.Font;
import javax.swing.JCheckBox;
import javax.swing.JTable;
import javax.swing.JScrollPane;
import javax.swing.JList;
import javax.swing.ListSelectionModel;
import java.awt.event.ActionListener;
import java.io.File;
import java.awt.event.ActionEvent;
import javax.swing.AbstractListModel;
import javax.swing.JComboBox;
import javax.swing.DefaultComboBoxModel;

public class SendMessageDialog extends JDialog {

	private final JPanel contentPanel = new JPanel();
	
	private boolean encryption;
	private boolean digital_sign;
	private boolean integrity_check;
	private boolean zip;
	private boolean radix;
	

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		try {
			SendMessageDialog dialog = new SendMessageDialog();
			dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
			dialog.setVisible(true);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	
	private void InitializeList(DefaultListModel<String> model) {
		
		ArrayList<UserInfo> userInfoList = (ArrayList<UserInfo>) KeyManager.getInstance().getUIUserInfo();
		
		Iterator<UserInfo> it = userInfoList.iterator();
		
		System.out.println("User info list " + userInfoList.size());
		
		while(it.hasNext()) {
			System.out.println("Adding");
			UserInfo item = (UserInfo) it.next();
			model.addElement(item.getEmail());
		}
		
	}

	/**
	 * Create the dialog.
	 */
	public SendMessageDialog() {
		setIconImage(Toolkit.getDefaultToolkit().getImage(SendMessageDialog.class.getResource("/com/sun/java/swing/plaf/windows/icons/Computer.gif")));
		setTitle("Send Message");
		setResizable(false);
		setBounds(100, 100, 795, 524);
		getContentPane().setLayout(null);
		contentPanel.setBounds(0, 0, 789, 454);
		contentPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		getContentPane().add(contentPanel);
		contentPanel.setLayout(null);
		{
			JLabel lblNewLabel = new JLabel("Please select options for Message Sending!");
			lblNewLabel.setFont(new Font("Tahoma", Font.BOLD, 17));
			lblNewLabel.setBounds(43, 13, 381, 38);
			contentPanel.add(lblNewLabel);
		}
		
		JCheckBox chckbxEncryption = new JCheckBox("Public Key Encryption");
		chckbxEncryption.setFont(new Font("Tahoma", Font.PLAIN, 16));
		chckbxEncryption.setBounds(29, 113, 181, 25);
		contentPanel.add(chckbxEncryption);
		
		JCheckBox chckbxDigitalSign = new JCheckBox("Digital Certification");
		
		chckbxDigitalSign.setFont(new Font("Tahoma", Font.PLAIN, 16));
		chckbxDigitalSign.setBounds(29, 195, 202, 25);
		contentPanel.add(chckbxDigitalSign);
		
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setBounds(535, 104, 225, 38);
		contentPanel.add(scrollPane);
		
		
		DefaultListModel<String> model = new DefaultListModel<>();
		InitializeList(model);
		JList<String> enc_list = new JList<>(model);
		enc_list.setEnabled(false);	
		scrollPane.setViewportView(enc_list);
		
	
		JScrollPane scrollPane_1 = new JScrollPane();
		scrollPane_1.setBounds(286, 185, 225, 38);
		contentPanel.add(scrollPane_1);
		
		DefaultListModel<String> model2 = new DefaultListModel<String>();
		InitializeList(model2);
		JList<String> sign_list = new JList<>(model2);
		sign_list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		sign_list.setEnabled(false);
		scrollPane_1.setViewportView(sign_list);

		
		JCheckBox chckbxZIP = new JCheckBox("ZIP Compression");
		chckbxZIP.setFont(new Font("Tahoma", Font.PLAIN, 16));
		chckbxZIP.setBounds(29, 267, 160, 25);
		contentPanel.add(chckbxZIP);
		
		JCheckBox chckbxRadix = new JCheckBox("Radix - 64 Conversion");
		chckbxRadix.setFont(new Font("Tahoma", Font.PLAIN, 16));
		chckbxRadix.setBounds(29, 338, 203, 25);
		contentPanel.add(chckbxRadix);
		
		JLabel lblFileName = new JLabel("");
		lblFileName.setFont(new Font("Tahoma", Font.PLAIN, 15));
		lblFileName.setBounds(535, 303, 225, 25);
		contentPanel.add(lblFileName);
		
		JButton btnNewButton = new JButton("Choose File");
		btnNewButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				final JFileChooser fileChooser = new JFileChooser(
						FileSystemView.getFileSystemView().getHomeDirectory());
				int result = fileChooser.showOpenDialog(contentPanel);
				if (result == JFileChooser.APPROVE_OPTION) {
					File selectedFile = fileChooser.getSelectedFile();
					
					lblFileName.setText(selectedFile.getName());
				}
			}
		});
		btnNewButton.setFont(new Font("Tahoma", Font.PLAIN, 16));
		btnNewButton.setBounds(286, 294, 225, 45);
		contentPanel.add(btnNewButton);
		
		JComboBox comboBox = new JComboBox();
		comboBox.setModel(new DefaultComboBoxModel(new String[] {"3DES + EDE", "CAST5"}));
		comboBox.setBounds(385, 104, 95, 38);
		contentPanel.add(comboBox);
		
		JCheckBox chckbxIntegrity = new JCheckBox("Integrity Check");
		chckbxIntegrity.setFont(new Font("Tahoma", Font.PLAIN, 16));
		chckbxIntegrity.setBounds(224, 113, 141, 25);
		contentPanel.add(chckbxIntegrity);
		

		{
			JPanel buttonPane = new JPanel();
			buttonPane.setBounds(0, 454, 789, 35);
			buttonPane.setLayout(new FlowLayout(FlowLayout.RIGHT));
			getContentPane().add(buttonPane);
			{
				JButton okButton = new JButton("OK");
				okButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						//OK BUTTON CLICKED
						
						if(digital_sign) {
							//Open password prompt
						}
						
					}
				});
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
		
		chckbxEncryption.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JCheckBox box = (JCheckBox) e.getSource();
				if(box.isSelected()) {
					encryption = true;
					enc_list.setEnabled(true);
				}
				else {
					encryption = false;
					enc_list.setEnabled(false);
				}
			}
		});
		
		
		chckbxDigitalSign.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JCheckBox box = (JCheckBox) e.getSource();
				if(box.isSelected()) {
					sign_list.setEnabled(true);
					digital_sign = true;
				}
				else {
					sign_list.setEnabled(false);
					digital_sign = false;
				}
			}
		});
		
		chckbxRadix.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JCheckBox box = (JCheckBox) e.getSource();
				if(box.isSelected())
					radix = true;
				else 
					radix = false;
		
			}
		});
		
		chckbxZIP.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JCheckBox box = (JCheckBox) e.getSource();
				if(box.isSelected())
					zip = true;
				else 
					zip = false;
		
			}
		});
		
		chckbxIntegrity.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JCheckBox box = (JCheckBox) e.getSource();
				if(box.isSelected())
					integrity_check = true;
				else 
					integrity_check = false;
			}
		});
	}
}
