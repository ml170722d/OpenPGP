package etf.openpgp.za170657d_ml170722d_GUI;

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

public class MainMenuWindow {

	private JFrame frmOpenPgp;

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
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frmOpenPgp = new JFrame();
		frmOpenPgp.setResizable(false);
		frmOpenPgp.setIconImage(Toolkit.getDefaultToolkit().getImage(MainMenuWindow.class.getResource("/javax/swing/plaf/metal/icons/ocean/computer.gif")));
		frmOpenPgp.setForeground(Color.WHITE);
		frmOpenPgp.setFont(new Font("Arial Black", Font.PLAIN, 16));
		frmOpenPgp.setTitle("Open PGP ");
		frmOpenPgp.setBounds(100, 100, 1122, 523);
		frmOpenPgp.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		
		JMenuBar menuBar = new JMenuBar();
		frmOpenPgp.setJMenuBar(menuBar);
		
		JMenu mnManageKeyPairs = new JMenu("Manage Key Pairs");
		mnManageKeyPairs.setFont(new Font("Segoe UI", Font.BOLD, 25));
		menuBar.add(mnManageKeyPairs);
		
		JMenuItem mntmAddNewKey = new JMenuItem("Add new Key Pair");
		mntmAddNewKey.setFont(new Font("Segoe UI", Font.BOLD, 18));
		mnManageKeyPairs.add(mntmAddNewKey);
		
		JMenuItem mntmDeleteKeyPair = new JMenuItem("Delete Key Pair");
		mntmDeleteKeyPair.setFont(new Font("Segoe UI", Font.BOLD, 18));
		mnManageKeyPairs.add(mntmDeleteKeyPair);
		
		JMenu mnNewMenu = new JMenu("Import/Export Key Pairs");
		mnNewMenu.setFont(new Font("Segoe UI", Font.BOLD, 25));
		menuBar.add(mnNewMenu);
		
		JMenuItem mntmNewMenuItem = new JMenuItem("Import Key Pair");
		mntmNewMenuItem.setFont(new Font("Segoe UI", Font.BOLD, 18));
		mnNewMenu.add(mntmNewMenuItem);
		
		JMenuItem mntmNewMenuItem_1 = new JMenuItem("Export Key Pair");
		mntmNewMenuItem_1.setFont(new Font("Segoe UI", Font.BOLD, 18));
		mnNewMenu.add(mntmNewMenuItem_1);
	}

}
