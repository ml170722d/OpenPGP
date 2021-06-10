package etf.openpgp.za170657d_ml170722d.GUI;

import java.awt.FlowLayout;

import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileSystemView;

import org.bouncycastle.openpgp.PGPPublicKey;

import java.awt.Toolkit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import javax.swing.JLabel;
import java.awt.Font;
import javax.swing.JCheckBox;
import javax.swing.JScrollPane;
import javax.swing.JList;
import javax.swing.ListSelectionModel;
import java.awt.event.ActionListener;
import java.io.File;
import java.awt.event.ActionEvent;
import javax.swing.JComboBox;
import javax.swing.DefaultComboBoxModel;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.ListSelectionEvent;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

import etf.openpgp.za170657d_ml170722d.securityV2.*;

public class SendMessageDialog extends JDialog {

	private static final long serialVersionUID = 1L;

	private final JPanel contentPanel = new JPanel();

	private boolean encryption;
	private boolean digital_sign;
	private boolean integrity_check;
	private boolean zip;
	private boolean radix;

	private String selectedAlg;
	private KeyRing signKey;
	private File selectedFile;

	ArrayList<PGPPublicKey> selectedKeyList = new ArrayList<PGPPublicKey>();
	private HashMap<String, Long> mapUserID_KeyID = new HashMap<String, Long>();

	private void InitializeList(DefaultListModel<String> model) {

		List<KeyRing> keyPairList = KeyChain.getChain();
		Iterator<KeyRing> it = keyPairList.iterator();

		System.out.println("User info list " + keyPairList.size());

		while (it.hasNext()) {
			KeyRing item = it.next();
			String arrSplit[] = item.getUserId().split("<");
			model.addElement(arrSplit[0].toString() + "-" + arrSplit[1].substring(0, arrSplit[1].length() - 1));
			mapUserID_KeyID.put(arrSplit[0].toString() + "-" + arrSplit[1].substring(0, arrSplit[1].length() - 1),
					item.getKeyId());
		}

	}

	public SendMessageDialog(int index, long keyID) {
		setIconImage(Toolkit.getDefaultToolkit()
				.getImage(SendMessageDialog.class.getResource("/com/sun/java/swing/plaf/windows/icons/Computer.gif")));
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

		JCheckBox chckbxEncryption = new JCheckBox("Encryption");
		chckbxEncryption.setFont(new Font("Tahoma", Font.PLAIN, 16));
		chckbxEncryption.setBounds(29, 113, 103, 25);
		contentPanel.add(chckbxEncryption);

		JCheckBox chckbxDigitalSign = new JCheckBox("Digital Certification");

		chckbxDigitalSign.setFont(new Font("Tahoma", Font.PLAIN, 16));
		chckbxDigitalSign.setBounds(29, 195, 163, 25);
		contentPanel.add(chckbxDigitalSign);

		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setBounds(535, 107, 225, 38);
		contentPanel.add(scrollPane);

		DefaultListModel<String> model = new DefaultListModel<>();
		InitializeList(model);
		JList<String> enc_list = new JList<>(model);
		// Public keys for encryptions!
		enc_list.addListSelectionListener(new ListSelectionListener() {
			public void valueChanged(ListSelectionEvent e) {
				if (!e.getValueIsAdjusting()) {

					JList list = (JList) e.getSource();

					List<String> str_list = list.getSelectedValuesList();

					selectedKeyList.clear();
					Iterator<String> it = str_list.iterator();

					while (it.hasNext()) {
						selectedKeyList.add(KeyChain.getKeyRing(mapUserID_KeyID.get(it.next())).getPublicKey());
					}
				}

			}
		});
		enc_list.setEnabled(false);
		scrollPane.setViewportView(enc_list);

		JScrollPane scrollPane_1 = new JScrollPane();
		scrollPane_1.setBounds(300, 188, 225, 40);
		contentPanel.add(scrollPane_1);

		DefaultListModel<String> model2 = new DefaultListModel<String>();
		InitializeList(model2);
		JList<String> sign_list = new JList<>(model2);
		// Private key for digital signature!
		sign_list.addListSelectionListener(new ListSelectionListener() {
			public void valueChanged(ListSelectionEvent e) {
				if (!e.getValueIsAdjusting()) {
					String selected_sign_key = sign_list.getSelectedValue();
					System.out.println("Private key " + signKey);
					signKey = KeyChain.getKeyRing(mapUserID_KeyID.get(selected_sign_key));
				}
			}
		});
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
					selectedFile = fileChooser.getSelectedFile();
					lblFileName.setText(selectedFile.getName());

					System.out.println("Abs file path " + selectedFile.getAbsolutePath() + " file  get name"
							+ selectedFile.getName());

				}
			}
		});
		btnNewButton.setFont(new Font("Tahoma", Font.PLAIN, 16));
		btnNewButton.setBounds(270, 285, 225, 45);
		contentPanel.add(btnNewButton);

		JComboBox comboBox = new JComboBox();
		comboBox.setEnabled(false);
		comboBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JComboBox comboBox = (JComboBox) e.getSource();
				selectedAlg = (String) comboBox.getSelectedItem();
				System.out.println("Selected " + selectedAlg);
			}
		});
		comboBox.setModel(new DefaultComboBoxModel(new String[] { "3DES + EDE", "CAST5" }));
		comboBox.setSelectedIndex(0);
		comboBox.setBounds(300, 105, 95, 38);
		contentPanel.add(comboBox);

		JCheckBox chckbxIntegrity = new JCheckBox("Integrity Check");
		chckbxIntegrity.setEnabled(false);
		chckbxIntegrity.setFont(new Font("Tahoma", Font.PLAIN, 16));
		chckbxIntegrity.setBounds(150, 113, 141, 25);
		contentPanel.add(chckbxIntegrity);

		JLabel lblNewLabel_1 = new JLabel("SENDER  : ");
		lblNewLabel_1.setFont(new Font("Tahoma", Font.BOLD, 15));
		lblNewLabel_1.setBounds(205, 187, 86, 40);
		contentPanel.add(lblNewLabel_1);

		JLabel lblNewLabel_2 = new JLabel("RECIVER/S  : ");
		lblNewLabel_2.setFont(new Font("Tahoma", Font.BOLD, 15));
		lblNewLabel_2.setBounds(415, 113, 104, 25);
		contentPanel.add(lblNewLabel_2);

		{
			JPanel buttonPane = new JPanel();
			buttonPane.setBounds(0, 454, 789, 35);
			buttonPane.setLayout(new FlowLayout(FlowLayout.RIGHT));
			getContentPane().add(buttonPane);
			{
				JButton okButton = new JButton("OK");
				okButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {

						if (selectedAlg.contains("3DES")) {
							try {
								Encryptor.enctyptFile(new File("").getAbsolutePath(), selectedFile.getAbsolutePath(),
										selectedFile.getName(), selectedKeyList, signKey.getSecretKey(),
										integrity_check, radix, encryption, SymmetricKeyAlgorithmTags.TRIPLE_DES, zip,
										digital_sign);
							} catch (Exception e1) {
								e1.printStackTrace();
							}
						} else if (selectedAlg.contains("CAST5")) {
							try {
								Encryptor.enctyptFile(new File("").getAbsolutePath(), selectedFile.getAbsolutePath(),
										selectedFile.getName(), selectedKeyList, signKey.getSecretKey(),
										integrity_check, radix, encryption, SymmetricKeyAlgorithmTags.CAST5, zip,
										digital_sign);
							} catch (Exception e1) {
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
				cancelButton.setActionCommand("Cancel");
				buttonPane.add(cancelButton);
			}
		}

		chckbxEncryption.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JCheckBox box = (JCheckBox) e.getSource();
				if (box.isSelected()) {
					encryption = true;
					enc_list.setEnabled(true);
					chckbxIntegrity.setEnabled(true);
					comboBox.setEnabled(true);
				} else {
					encryption = false;
					enc_list.setEnabled(false);
					chckbxIntegrity.setEnabled(false);
					comboBox.setEnabled(false);
				}
			}
		});

		chckbxDigitalSign.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JCheckBox box = (JCheckBox) e.getSource();
				if (box.isSelected()) {
					sign_list.setEnabled(true);
					digital_sign = true;
				} else {
					sign_list.setEnabled(false);
					digital_sign = false;
				}
			}
		});

		chckbxRadix.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JCheckBox box = (JCheckBox) e.getSource();
				if (box.isSelected())
					radix = true;
				else
					radix = false;

			}
		});

		chckbxZIP.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JCheckBox box = (JCheckBox) e.getSource();
				if (box.isSelected())
					zip = true;
				else
					zip = false;

			}
		});

		chckbxIntegrity.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JCheckBox box = (JCheckBox) e.getSource();
				if (box.isSelected())
					integrity_check = true;
				else
					integrity_check = false;
			}
		});
	}
}
