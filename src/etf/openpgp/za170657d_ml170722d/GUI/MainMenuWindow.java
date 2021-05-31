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
import javax.swing.JTextArea;
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
import javax.swing.table.DefaultTableModel;
import javax.swing.ListSelectionModel;

public class MainMenuWindow {

	private JFrame frmOpenPgp;

	private File importedKeyFile;
	private JTable table;

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


//		remove key ring from key manager
//		KeyManager.getInstance().deleteKey(ind, password);
		
	
		
	}
	

	public void addKeyPair() {
		System.out.println("Add new key pair");
		ArrayList<UserInfo> list = (ArrayList<UserInfo>) KeyManager.getInstance().getUIUserInfo();

		Iterator it = list.iterator();
		
		while(it.hasNext()) {
		 UserInfo item = (UserInfo) it.next();
		 
		 
		 
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
	             e.getWindow().dispose();
	         }
	     });

		mntmAddNewKey.setFont(new Font("Segoe UI", Font.BOLD, 18));
		mnManageKeyPairs.add(mntmAddNewKey);

		JMenuItem mntmDeleteKeyPair = new JMenuItem("Delete Key Pair");
		// This action listener if onClick listener for Delete Key Pair menu item
		// This listener invokes dialog for deleting existing Key Pair
		mntmDeleteKeyPair.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				// well not yet
				// Your code goes here ####
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

		JMenu mnNewMenu = new JMenu("Decrypt/Encrypt file");
		mnNewMenu.setFont(new Font("Segoe UI", Font.BOLD, 20));
		menuBar.add(mnNewMenu);

		JMenuItem mntmNewMenuItem_2 = new JMenuItem("Encrypt file");
		mntmNewMenuItem_2.setFont(new Font("Segoe UI", Font.BOLD, 18));
		mnNewMenu.add(mntmNewMenuItem_2);

		JMenuItem mntmNewMenuItem_3 = new JMenuItem("Decrypt file");
		mntmNewMenuItem_3.setFont(new Font("Segoe UI", Font.BOLD, 18));
		mnNewMenu.add(mntmNewMenuItem_3);
		frmOpenPgp.getContentPane().setLayout(null);
		
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setBounds(120, 52, 872, 340);
		frmOpenPgp.getContentPane().add(scrollPane);
		
		
		String columnNames[] = {"E-Mail","Key-ID","Valid From"};
		
		String data[][] = {
				{"Temp","Temp","Temp"}
		};
		
		table = new JTable(data,columnNames);
		table.setFont(new Font("Arial Black", Font.PLAIN, 15));
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		scrollPane.setViewportView(table);
		table.setBorder(null);
		table.setBounds(0, 0, 1, 1);
		
		

		
		

	
	}
}
