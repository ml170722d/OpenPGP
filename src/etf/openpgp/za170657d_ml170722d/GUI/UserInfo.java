package etf.openpgp.za170657d_ml170722d.GUI;

import java.text.Format;
import java.text.SimpleDateFormat;
import java.util.Date;

public class UserInfo {

	private String email;
	private int index;
	private Date validDateFrom;
	private long keyId;

	public UserInfo(int index, String email, Date validFRom, long keyId) {
		this.email = email;
		this.index = index;
		this.validDateFrom = validFRom;
		this.keyId = keyId;
	}

	public String getEmail() {
		return email;
	}

	public int getIndex() {
		return index;
	}

	public Date getValidDateFrom() {
		return validDateFrom;
	}

	public long getKeyId() {
		return keyId;
	}

	@Override
	public String toString() {
		Format date = new SimpleDateFormat("dd-MM-yyyy");
		return index + " " + email + " " + date.format(validDateFrom) + " " + keyId;
	}
}
