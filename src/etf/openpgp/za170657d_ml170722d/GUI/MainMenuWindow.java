package etf.openpgp.za170657d_ml170722d.GUI;

import java.awt.EventQueue;

import javax.swing.JFrame;
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

import etf.openpgp.za170657d_ml170722d.security.KeyManager;

import javax.swing.JLabel;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JScrollPane;
import java.awt.GridLayout;
import javax.swing.JTable;
import javax.swing.border.LineBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
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
		try {
			KeyManager.getInstance().loadKeyRings();
		} catch (PGPException e) {
			e.printStackTrace();
		}

		initializeKeyPairTable();
		userInfoList = KeyManager.getInstance().getUIUserInfo();
//		remove key ring from key manager
//		KeyManager.getInstance().deleteKey(ind, password);
		
	}
	

	/**
	 * Reads from file where the key pairs are stored and adds them to the key pair table.
	 */
	public void initializeKeyPairTable() {
		System.out.println("Add new key pair");
		ArrayList<UserInfo> list = (ArrayList<UserInfo>) KeyManager.getInstance().getUIUserInfo();

		Iterator it = list.iterator();
		
		while(it.hasNext()) {	
		 UserInfo item = (UserInfo) it.next();
		 AddTableRow(item);
		}
		
	}

	/**
	 * Adds single key pair (row) to the key pair table.
	 */
	public void addKeyPair() {
		
		ArrayList<UserInfo> list = (ArrayList<UserInfo>) KeyManager.getInstance().getUIUserInfo();
		UserInfo item = (UserInfo) list.get(list.size()-1);
		AddTableRow(item);
		
	}
	
	/**
	 * Adds rows to the table.
	 * @param userInfo - data for the new row
	 */
	private void AddTableRow(UserInfo userInfo) {
		
		 DefaultTableModel model = (DefaultTableModel) keyPairTable.getModel();
		 String rowData[] = new String[3];
		 rowData[0] = userInfo.getEmail();
		 rowData[1] = Long.toString(userInfo.getKeyId());
		 rowData[2] = userInfo.getValidDateFrom().toString();
		 model.insertRow(model.getRowCount(), rowData);
		
	}
	private void RemoveTableRow() {
		
		Iterator it = this.userInfoList.iterator();
		System.out.println("Remove Table row!");
		DefaultTableModel model = (DefaultTableModel) keyPairTable.getModel();
		
		int i = 0;
		while(i < keyPairTable.getRowCount()) {
			System.out.println("Deleting the row");
			long temp_key_Id = Long.parseLong((String)model.getValueAt(i, 1));
			if(temp_key_Id == selectedKeyId) {
				model.removeRow(i);
				
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
		
		//listener for window closing
		frmOpenPgp.addWindowListener(new WindowAdapter()
	     {
	       
			@Override
	         public void windowClosing(WindowEvent e)
	         {
	             System.out.println("Closed");
	             KeyManager.getInstance().storeKeyRings();
	             e.getWindow().dispose();//discordapp.com/channels/@me
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
				KeyPairRemovalDialog dialog = new KeyPairRemovalDialog(host,host.selectedKeyIndex);
				dialog.setVisible(true);
				if(dialog.isSuccess()) {
					dialog.setSuccess(false);
					mntmDeleteKeyPair.setEnabled(false);
					host.RemoveTableRow();	
				}
				
			}
		});
		mntmDeleteKeyPair.setFont(new Font("Segoe UI", Font.BOLD, 18));
		mnManageKeyPairs.add(mntmDeleteKeyPair);

		JMenu ExportImportMenu = new JMenu("Import/Export Key Pairs");
		ExportImportMenu.setFont(new Font("Segoe UI", Font.BOLD, 20));
		menuBar.add(ExportImportMenu);

		JMenuItem mntmNewMenuItem = new JMenuItem("Import Key Pair");
		// System file dialog for file choosing(Import).
		mntmNewMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				final JFileChooser fileChooser = new JFileChooser(
						FileSystemView.getFileSystemView().getHomeDirectory());
				int result = fileChooser.showOpenDialog(frmOpenPgp);
				if (result == JFileChooser.APPROVE_OPTION) {
					importedKeyFile = fileChooser.getSelectedFile();
					// opened file!
				}

			}
		});
		mntmNewMenuItem.setFont(new Font("Segoe UI", Font.BOLD, 18));
		ExportImportMenu.add(mntmNewMenuItem);

		JMenuItem mntmNewMenuItem_1 = new JMenuItem("Export Key Pair");
		// System file dialog for file saving(Export).
		mntmNewMenuItem_1.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				final JFileChooser fileChooser = new JFileChooser(
						FileSystemView.getFileSystemView().getHomeDirectory());
				int result = fileChooser.showSaveDialog(frmOpenPgp);
				if (result == JFileChooser.APPROVE_OPTION) {
					// Code for file saving?
				}
			}
		});
		
		
		
		mntmNewMenuItem_1.setFont(new Font("Segoe UI", Font.BOLD, 18));
		ExportImportMenu.add(mntmNewMenuItem_1);

		JMenu mnNewMenu = new JMenu("Send/Recive Message");
		mnNewMenu.setFont(new Font("Segoe UI", Font.BOLD, 20));
		menuBar.add(mnNewMenu);

		JMenuItem mntmNewMenuItem_2 = new JMenuItem("Send Message");
		mntmNewMenuItem_2.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				new SendMessageDialog().setVisible(true);
			}
		});
		mntmNewMenuItem_2.setFont(new Font("Segoe UI", Font.BOLD, 18));
		mnNewMenu.add(mntmNewMenuItem_2);

		JMenuItem mntmNewMenuItem_3 = new JMenuItem("Recive Message");
		mntmNewMenuItem_3.setFont(new Font("Segoe UI", Font.BOLD, 18));
		mnNewMenu.add(mntmNewMenuItem_3);
		frmOpenPgp.getContentPane().setLayout(null);
		
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setBounds(120, 52, 872, 340);
		frmOpenPgp.getContentPane().add(scrollPane);
		
		
		
		DefaultTableModel tabelModel = new DefaultTableModel();
		
		keyPairTable = new JTable(tabelModel);
		tabelModel.addColumn("E-Mail");
		tabelModel.addColumn("Key-ID");
		tabelModel.addColumn("Valid From");
		keyPairTable.setFont(new Font("Arial Black", Font.PLAIN, 15));
		keyPairTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		scrollPane.setViewportView(keyPairTable);
		keyPairTable.setBorder(null);
		keyPairTable.setBounds(0, 0, 1, 1);
		
		

		
		keyPairTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
			
			@Override
			public void valueChanged(ListSelectionEvent e) {
				// TODO Auto-generated method stub
				if(!e.getValueIsAdjusting() && keyPairTable.getSelectedRow()!=-1) {
					String keyID = (String) keyPairTable.getValueAt(keyPairTable.getSelectedRow(), 1);
					selectedKeyId = Long.parseLong(keyID);
					mntmDeleteKeyPair.setEnabled(true);
					
					//Find index of selected key pair, by the key id;
					System.out.println("Selected");
					Iterator it = userInfoList.iterator();
					int index = -1;
					while(it.hasNext()) {
						
						System.out.println("Search");
						UserInfo item = (UserInfo) it.next();
						if(item.getKeyId() == Long.parseLong(keyID)) {
							host.selectedKeyIndex = item.getIndex();
							System.out.println("Key ID " + keyID + " Index " + host.selectedKeyIndex);
							break;
						}
					}
				}
			}
		});

	
	}
}
