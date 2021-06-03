package etf.openpgp.za170657d_ml170722d.GUI;

import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

public class EnterPasswordPanel extends JPanel {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private char[] password;
	
	public EnterPasswordPanel(int attemptsLeft) {
		JLabel label = new JLabel("Enter password: ("+attemptsLeft+" attempts left)");
		JPasswordField pass = new JPasswordField(30);
		this.add(label);
		this.add(pass);

		String[] opt = new String[] { "OK", "Cancel" };
		int option = JOptionPane.showOptionDialog(null, this, "Secret key requires password", JOptionPane.NO_OPTION,
				JOptionPane.WARNING_MESSAGE, null, opt, opt[1]);
		
		if (option==0) {
			password=pass.getPassword();
		}
	}
	
	public char[] getPassword() {
		return password;
	}
}
