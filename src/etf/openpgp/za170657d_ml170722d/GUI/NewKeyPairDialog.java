package etf.openpgp.za170657d_ml170722d.GUI;

import java.awt.BorderLayout;
import java.awt.FlowLayout;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import java.awt.Font;
import javax.swing.JLabel;
import javax.swing.JTextField;
import java.awt.Color;
import javax.swing.JComboBox;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.Toolkit;

public class NewKeyPairDialog extends JDialog {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private final JPanel contentPanel = new JPanel();
	private MainMenuWindow mainWindow;
	private JTextField nameTextField;
	private JTextField emailTextField;

	// selected key size
	private int selectedKeySize = 2048;
	private String user_name;
	private String user_email;

	public int getSelectedKeySize() {
		return selectedKeySize;
	}

	public String getUser_name() {
		return user_name;
	}

	public String getUser_email() {
		return user_email;
	}

	/**
	 * Create the dialog.
	 */
	public NewKeyPairDialog(MainMenuWindow mainWindow) {
		setIconImage(Toolkit.getDefaultToolkit().getImage(NewKeyPairDialog.class.getResource("/javax/swing/plaf/metal/icons/ocean/collapsed.gif")));

		this.mainWindow = mainWindow;

		setFont(new Font("Dialog", Font.BOLD, 16));
		setTitle("New Key Pair Generator");
		setResizable(false);
		setBounds(100, 100, 629, 399);
		getContentPane().setLayout(new BorderLayout());
		contentPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		getContentPane().add(contentPanel, BorderLayout.CENTER);
		contentPanel.setLayout(null);
		{
			JLabel lblNewLabel = new JLabel("Please enter all the necessary details!");
			lblNewLabel.setFont(new Font("Tahoma", Font.BOLD, 25));
			lblNewLabel.setBounds(60, 27, 530, 56);
			contentPanel.add(lblNewLabel);
		}
		{
			JLabel lblNewLabel_1 = new JLabel("Name :");
			lblNewLabel_1.setFont(new Font("Tahoma", Font.PLAIN, 16));
			lblNewLabel_1.setBounds(26, 123, 56, 16);
			contentPanel.add(lblNewLabel_1);
		}
		{
			JLabel lblEmail = new JLabel("E-Mail :");
			lblEmail.setFont(new Font("Tahoma", Font.PLAIN, 16));
			lblEmail.setBounds(26, 206, 56, 16);
			contentPanel.add(lblEmail);
		}

		nameTextField = new JTextField();
		nameTextField.setFont(new Font("Tahoma", Font.PLAIN, 15));
		nameTextField.setBounds(91, 121, 306, 22);
		contentPanel.add(nameTextField);
		nameTextField.setColumns(10);

		emailTextField = new JTextField();
		emailTextField.setFont(new Font("Tahoma", Font.PLAIN, 15));
		emailTextField.setBounds(95, 204, 302, 22);
		contentPanel.add(emailTextField);
		emailTextField.setColumns(10);

		JLabel lblNoteFor = new JLabel("Note : For signing and encryption we are using RSA algorithm");
		lblNoteFor.setForeground(new Color(30, 144, 255));
		lblNoteFor.setFont(new Font("Tahoma", Font.PLAIN, 14));
		lblNoteFor.setBounds(26, 274, 381, 22);
		contentPanel.add(lblNoteFor);

		String keySizes[] = { "1024", "2048", "4096" };
		JComboBox comboBox = new JComboBox(keySizes);
		comboBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {

				String selectedItem = (String) comboBox.getSelectedItem();
				selectedKeySize = Integer.parseInt(selectedItem);

			}

		});
		comboBox.setFont(new Font("Tahoma", Font.PLAIN, 15));
		comboBox.setBounds(534, 121, 64, 22);
		contentPanel.add(comboBox);

		JLabel lblNewLabel_2 = new JLabel("Key Size :");
		lblNewLabel_2.setFont(new Font("Tahoma", Font.PLAIN, 16));
		lblNewLabel_2.setBounds(455, 123, 80, 16);
		contentPanel.add(lblNewLabel_2);
		{
			JPanel buttonPane = new JPanel();
			buttonPane.setLayout(new FlowLayout(FlowLayout.RIGHT));
			getContentPane().add(buttonPane, BorderLayout.SOUTH);
			{
				JButton okButton = new JButton("OK");
				okButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						user_name = nameTextField.getText();
						user_email = emailTextField.getText();
						// Display error because user didnt enter the user name or email
						if (user_name.equals("") || user_email.equals("")) {
							lblNoteFor.setText("Please enter valid data for user name and email");
							lblNoteFor.setForeground(Color.RED);

						} else {
							new PassPhraseDialog(mainWindow, user_name + "<" + user_email + ">", selectedKeySize)
									.setVisible(true);
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
				// Closing the New Key Pair Dialog
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
