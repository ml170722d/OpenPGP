package etf.openpgp.za170657d_ml170722d.GUI;

import java.awt.BorderLayout;
import java.awt.FlowLayout;

import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

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
import java.awt.event.ActionEvent;

public class SendMessageDialog extends JDialog {

	private final JPanel contentPanel = new JPanel();
	

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
		setBounds(100, 100, 744, 524);
		getContentPane().setLayout(null);
		contentPanel.setBounds(0, 0, 738, 454);
		contentPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		getContentPane().add(contentPanel);
		contentPanel.setLayout(null);
		{
			JLabel lblNewLabel = new JLabel("Please select options for Message Sending!");
			lblNewLabel.setFont(new Font("Tahoma", Font.BOLD, 17));
			lblNewLabel.setBounds(43, 13, 381, 38);
			contentPanel.add(lblNewLabel);
		}
		
		JCheckBox chckbxNewCheckBox = new JCheckBox("Public Key Encryption");
		chckbxNewCheckBox.setFont(new Font("Tahoma", Font.PLAIN, 16));
		chckbxNewCheckBox.setBounds(62, 117, 202, 25);
		contentPanel.add(chckbxNewCheckBox);
		
		JCheckBox chckbxNewCheckBox_1 = new JCheckBox("Digital Certification");
		
		chckbxNewCheckBox_1.setFont(new Font("Tahoma", Font.PLAIN, 16));
		chckbxNewCheckBox_1.setBounds(62, 195, 202, 25);
		contentPanel.add(chckbxNewCheckBox_1);
		
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setBounds(351, 106, 225, 38);
		contentPanel.add(scrollPane);
		
		
		DefaultListModel<String> model = new DefaultListModel<>();
		InitializeList(model);
		JList<String> enc_list = new JList<>(model);
		enc_list.setEnabled(false);	
		scrollPane.setViewportView(enc_list);
		
	
		JScrollPane scrollPane_1 = new JScrollPane();
		scrollPane_1.setBounds(351, 182, 225, 38);
		contentPanel.add(scrollPane_1);
		
		DefaultListModel<String> model2 = new DefaultListModel<String>();
		InitializeList(model2);
		JList<String> sign_list = new JList<>(model2);
		sign_list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		sign_list.setEnabled(false);
		scrollPane_1.setColumnHeaderView(sign_list);

		
		JCheckBox chckbxNewCheckBox_2 = new JCheckBox("ZIP Compression");
		chckbxNewCheckBox_2.setFont(new Font("Tahoma", Font.PLAIN, 16));
		chckbxNewCheckBox_2.setBounds(62, 267, 160, 25);
		contentPanel.add(chckbxNewCheckBox_2);
		
		JCheckBox chckbxNewCheckBox_3 = new JCheckBox("Radix - 64 Conversion");
		chckbxNewCheckBox_3.setFont(new Font("Tahoma", Font.PLAIN, 16));
		chckbxNewCheckBox_3.setBounds(62, 338, 203, 25);
		contentPanel.add(chckbxNewCheckBox_3);
		
		JButton btnNewButton = new JButton("Choose File");
		btnNewButton.setFont(new Font("Tahoma", Font.PLAIN, 16));
		btnNewButton.setBounds(351, 287, 225, 45);
		contentPanel.add(btnNewButton);
		{
			JPanel buttonPane = new JPanel();
			buttonPane.setBounds(0, 454, 738, 35);
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
		
		chckbxNewCheckBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JCheckBox box = (JCheckBox) e.getSource();
				if(box.isSelected())
					enc_list.setEnabled(true);
				else
					enc_list.setEnabled(false);
			}
		});
		
		chckbxNewCheckBox_1.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JCheckBox box = (JCheckBox) e.getSource();
				if(box.isSelected())
					sign_list.setEnabled(true);
				else
					sign_list.setEnabled(false);
			}
		});
	}
}
