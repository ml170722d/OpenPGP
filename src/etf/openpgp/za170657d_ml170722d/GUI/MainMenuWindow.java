package etf.openpgp.za170657d_ml170722d.GUI;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.security.auth.kerberos.KerberosKey;
import javax.swing.JDesktopPane;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import javax.swing.JMenuBar;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import java.awt.Font;
import java.awt.Color;
import java.awt.Toolkit;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileSystemView;

import org.bouncycastle.openpgp.PGPException;

import etf.openpgp.za170657d_ml170722d.security.error.AlreadyInUse;
import etf.openpgp.za170657d_ml170722d.securityV2.KeyChain;
import etf.openpgp.za170657d_ml170722d.securityV2.KeyManager;
import etf.openpgp.za170657d_ml170722d.securityV2.KeyRing;

import javax.swing.JLabel;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JScrollPane;
import java.awt.GridLayout;
import java.awt.RenderingHints.Key;

import javax.swing.JTable;
import javax.swing.border.LineBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import javax.swing.ListSelectionModel;

public class MainMenuWindow {

	private JFrame frmOpenPgp;

	private File importedKeyFile;
	private JTable keyPairTable;

	private int selectedKeyIndex;
	private long selectedKeyId;
	public List<UserInfo> userInfoList;

	public File getImportedKeyFile() {
		return importedKeyFile;
	}

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					MainMenuWindow window = new MainMenuWindow();
					window.frmOpenPgp.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public MainMenuWindow() {
		initialize(this);
		java.security.Security.setProperty("crypto.policy", "unlimited");
		KeyManager.init();
		KeyManager.loadKeyChain();
		initializeKeyPairTable();
	}

	/**
	 * Reads from file where the key pairs are stored and adds them to the key pair
	 * table.
	 */
	public void initializeKeyPairTable() {
		System.out.println("Add new key pair");
		
		List<KeyRing> data_list = KeyChain.getChain();
		Iterator<KeyRing> it = data_list.iterator();
		
		System.out.println("Initialize " + data_list.size());
		
		while (it.hasNext()) {
			KeyRing item = it.next();
			AddTableRow(item);
		}

	}

	/**
	 * Adds single key pair (row) to the key pair table.
	 */
	public void addKeyPair() {

		List<KeyRing> list = KeyChain.getChain();
		KeyRing item = (KeyRing) list.get(list.size() - 1);
		AddTableRow(item);

	}

	/**
	 * Adds rows to the table.
	 * 
	 * @param userInfo - data for the new row
	 */
	private void AddTableRow(KeyRing keyRing) {

		DefaultTableModel model = (DefaultTableModel) keyPairTable.getModel();
		String rowData[] = new String[5];
		String arrSplit[] = keyRing.getUserId().split("<");
		rowData[0] = arrSplit[0];
		rowData[1] = arrSplit[1].substring(0, arrSplit[1].length() - 1);
		rowData[2] = Long.toString(keyRing.getKeyId());
		rowData[3] = keyRing.getCreationDate().toString();
		rowData[4] = "";
		
		if (keyRing.hasPrivateKey() && keyRing.hasPublicKey())
			rowData[4] = "PU-PR";
		else if(keyRing.hasPrivateKey() && !keyRing.hasPublicKey())
			rowData[4] = "PR";
		else if(!keyRing.hasPrivateKey() && keyRing.hasPublicKey())
			rowData[4] = "PU";
		else 
			rowData[4] = "";

		

		model.insertRow(model.getRowCount(), rowData);

	}

	// treba da prodje kroz tabelu vidi jel ima tog kljuca i da mu dodeli onaj flag
	// ako nema kljuca ubaci nov red

	private void UpdateTableAfterImport() {

		DefaultTableModel model = (DefaultTableModel) keyPairTable.getModel();
		String rowData[] = new String[5];


		
		KeyRing keyRing = KeyChain.getChain().get(KeyChain.getChain().size() - 1);
		
	
		

		String arrSplit[] = keyRing.getUserId().split("<");
		rowData[0] = arrSplit[0];
		rowData[1] = arrSplit[1].substring(0, arrSplit[1].length() - 1);
		rowData[2] = Long.toString(keyRing.getKeyId());
		rowData[3] = keyRing.getCreationDate().toString();

		rowData[4] = "";
		
		if (keyRing.hasPrivateKey() && keyRing.hasPublicKey())
			rowData[4] = "PU-PR";
		else if(keyRing.hasPrivateKey() && !keyRing.hasPublicKey())
			rowData[4] = "PR";
		else if(!keyRing.hasPrivateKey() && keyRing.hasPublicKey())
			rowData[4] = "PU";
		else 
			rowData[4] = "";
		

		model.insertRow(model.getRowCount(), rowData);

	}

	private void RemoveTableRow() {

		Iterator it = KeyChain.getChain().iterator();
		System.out.println("Remove Table row!");
		DefaultTableModel model = (DefaultTableModel) keyPairTable.getModel();

		int i = 0;
		while (i < keyPairTable.getRowCount()) {
			System.out.println("Deleting the row");
			long temp_key_Id = Long.parseLong((String) model.getValueAt(i, 2));
			if (temp_key_Id == selectedKeyId) {

				KeyRing item = KeyChain.getKeyRing(selectedKeyId);

				if (item == null) {
					model.removeRow(i);
					break;
				}
				if (item.hasPrivateKey() && !item.hasPublicKey()) {
					model.setValueAt("PR", i, 4);
				} else if (!item.hasPrivateKey() && item.hasPublicKey()) {
					model.setValueAt("PU", i, 4);
				}

				break;
			}

			i++;
		}

	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize(MainMenuWindow host) {
		frmOpenPgp = new JFrame();
		frmOpenPgp.setResizable(false);
		frmOpenPgp.setIconImage(Toolkit.getDefaultToolkit()
				.getImage(MainMenuWindow.class.getResource("/javax/swing/plaf/metal/icons/ocean/computer.gif")));
		frmOpenPgp.setForeground(Color.WHITE);
		frmOpenPgp.setFont(new Font("Arial Black", Font.PLAIN, 16));
		frmOpenPgp.setTitle("Open PGP ");
		frmOpenPgp.setBounds(100, 100, 1122, 523);
		frmOpenPgp.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

		JMenuBar menuBar = new JMenuBar();
		frmOpenPgp.setJMenuBar(menuBar);

		JMenu mnManageKeyPairs = new JMenu("Manage Key Pairs");
		mnManageKeyPairs.setFont(new Font("Segoe UI", Font.BOLD, 20));
		menuBar.add(mnManageKeyPairs);

		JMenuItem mntmAddNewKey = new JMenuItem("Add new Key Pair");
		// This action listener if onClick listener for Add new Key Pair menu item
		// This listener invokes dialog for new Key Pair making.
		mntmAddNewKey.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				System.out.println("Clicked");
				new NewKeyPairDialog(host).setVisible(true);
				// Your code goes here ####
			}
		});

		// listener for window closing
		frmOpenPgp.addWindowListener(new WindowAdapter() {

			@Override
			public void windowClosing(WindowEvent e) {
				System.out.println("Closed");
				KeyManager.storeKeyChain();
				e.getWindow().dispose();// discordapp.com/channels/@me
			}
		});

		mntmAddNewKey.setFont(new Font("Segoe UI", Font.BOLD, 18));
		mnManageKeyPairs.add(mntmAddNewKey);

		JMenuItem mntmDeleteKeyPair = new JMenuItem("Delete Key Pair");
		mntmDeleteKeyPair.setEnabled(false);
		// This action listener if onClick listener for Delete Key Pair menu item
		// This listener invokes dialog for deleting existing Key Pair
		mntmDeleteKeyPair.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				System.out.println("Delete key");
				for (int i = 0; i < KeyChain.getChain().size(); i++) {
					System.out.println(i + " " + KeyChain.getKeyRing(i).getKeyId());
				}
				KeyPairRemovalDialog dialog = new KeyPairRemovalDialog(host, host.selectedKeyId);
				dialog.setVisible(true);
				if (dialog.isSuccess()) {
					dialog.setSuccess(false);
					mntmDeleteKeyPair.setEnabled(false);
					try {
						host.RemoveTableRow();
					} catch (Exception e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				}

			}
		});
		mntmDeleteKeyPair.setFont(new Font("Segoe UI", Font.BOLD, 18));
		mnManageKeyPairs.add(mntmDeleteKeyPair);

		JMenu ExportImportMenu = new JMenu("Import/Export Key Pairs");
		ExportImportMenu.setFont(new Font("Segoe UI", Font.BOLD, 20));
		menuBar.add(ExportImportMenu);

		JMenuItem ImportMenuItem = new JMenuItem("Import Key Pair");
		// System file dialog for file choosing.
		// Import
		ImportMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				final JFileChooser fileChooser = new JFileChooser(new File("").getAbsoluteFile());
				int result = fileChooser.showOpenDialog(frmOpenPgp);
				if (result == JFileChooser.APPROVE_OPTION) {
					File selectedFile = fileChooser.getSelectedFile();
					System.out.println("Selected file + " + selectedFile.getAbsolutePath());
					try {
						KeyManager.importKeyRingFromFile(selectedFile.getAbsolutePath());
						DefaultTableModel model = (DefaultTableModel) keyPairTable.getModel();
						model.setRowCount(0);
						keyPairTable.revalidate();
						initializeKeyPairTable();
					} catch (AlreadyInUse e1) {
						// Key is already loaded in application!!!
						// No need to update table in gui
						e1.printStackTrace();
					}
				}

			}
		});
		ImportMenuItem.setFont(new Font("Segoe UI", Font.BOLD, 18));
		ExportImportMenu.add(ImportMenuItem);

		JMenuItem ExportMenuItem = new JMenuItem("Export Key Pair");
		ExportMenuItem.setEnabled(false);
		// System file dialog for file saving.
		// Export
		ExportMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				ExportDialog dialog = new ExportDialog(selectedKeyId, selectedKeyIndex);
				dialog.setVisible(true);
			}
		});

		ExportMenuItem.setFont(new Font("Segoe UI", Font.BOLD, 18));
		ExportImportMenu.add(ExportMenuItem);

		JMenu mnNewMenu = new JMenu("Send/Recive Message");
		mnNewMenu.setFont(new Font("Segoe UI", Font.BOLD, 20));
		menuBar.add(mnNewMenu);

		// SEND MESSAGE
		JMenuItem SendMessageMenuItem = new JMenuItem("Send Message");
		SendMessageMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				new SendMessageDialog(selectedKeyIndex, selectedKeyId).setVisible(true);
			}
		});
		SendMessageMenuItem.setFont(new Font("Segoe UI", Font.BOLD, 18));
		mnNewMenu.add(SendMessageMenuItem);

		JMenuItem ReciveMessageMenuItem = new JMenuItem("Recive Message");
		ReciveMessageMenuItem.setFont(new Font("Segoe UI", Font.BOLD, 18));
		mnNewMenu.add(ReciveMessageMenuItem);
		frmOpenPgp.getContentPane().setLayout(null);

		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setBounds(120, 52, 872, 340);
		frmOpenPgp.getContentPane().add(scrollPane);

		DefaultTableModel tabelModel = new DefaultTableModel();
		keyPairTable = new JTable(tabelModel);
		tabelModel.addColumn("User Name");
		tabelModel.addColumn("E-Mail");
		tabelModel.addColumn("Key-ID");
		tabelModel.addColumn("Valid From");
		tabelModel.addColumn("Keys Status");
		keyPairTable.setFont(new Font("Arial Black", Font.PLAIN, 15));
		keyPairTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		scrollPane.setViewportView(keyPairTable);
		keyPairTable.setBorder(null);
		keyPairTable.setBounds(0, 0, 1, 1);

		keyPairTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {

			@Override
			public void valueChanged(ListSelectionEvent e) {
				// TODO Auto-generated method stub
				if (!e.getValueIsAdjusting() && keyPairTable.getSelectedRow() != -1) {
					String keyID = (String) keyPairTable.getValueAt(keyPairTable.getSelectedRow(), 2);
					selectedKeyId = Long.parseLong(keyID);

					mntmDeleteKeyPair.setEnabled(true);
					ExportMenuItem.setEnabled(true);
				

					System.out.println("Selected");
					System.out.println("Key ID " + keyID);

					try {
						KeyRing keyRing = KeyChain.getKeyRing(selectedKeyId);

						List<KeyRing> data_list = KeyChain.getChain();
						Iterator<KeyRing> it = data_list.iterator();

						int count = 0;

						while (it.hasNext()) {
							KeyRing item = it.next();
							if (item.getKeyId() == selectedKeyId) {
								selectedKeyIndex = count;
								break;
							}
							count++;
						}

					} catch (Exception e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}

					System.out.println("Key ID " + keyID + " Index " + selectedKeyIndex);

				}
			}
		});

	}
}
