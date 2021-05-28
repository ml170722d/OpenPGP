package etf.openpgp.za170657d_ml170722d.security;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

public class KeyRing {

	private PGPSecretKeyRing secretKeyRing = null;
	private PGPPublicKeyRing publicKeyRing = null;

	public static enum KEYRINGTYPE {
		PUBLIC, SECRET, PUBLIC_SECRET
	}

	/**
	 * Constructor
	 * 
	 * @param secretKeyRing secrete key ring
	 */
	public KeyRing(PGPSecretKeyRing secretKeyRing) {
		this.secretKeyRing = secretKeyRing;
	}

	/**
	 * Constructor
	 * 
	 * @param publicKeyRing public key ring
	 */
	public KeyRing(PGPPublicKeyRing publicKeyRing) {
		this.publicKeyRing = publicKeyRing;
	}

	/**
	 * Constructor
	 * 
	 * @param secretKeyRing secrete key ring
	 * @param publicKeyRing public key ring
	 */
	public KeyRing(PGPSecretKeyRing secretKeyRing, PGPPublicKeyRing publicKeyRing) {
		this.secretKeyRing = secretKeyRing;
		this.publicKeyRing = publicKeyRing;
	}

	/**
	 * Constructor
	 * 
	 * @param secretKeyRingEncoded byte array of encoded secrete key ring
	 * @param publicKeyRingEncoded byte array of encoded public key ring
	 */
	public KeyRing(byte[] secretKeyRingEncoded, byte[] publicKeyRingEncoded) {
		try {
			if (secretKeyRingEncoded.length > 0)
				secretKeyRing = new PGPSecretKeyRing(secretKeyRingEncoded, new JcaKeyFingerprintCalculator());
		} catch (IOException | PGPException e) {
			e.printStackTrace();
		}

		try {
			if (publicKeyRingEncoded.length > 0)
				publicKeyRing = new PGPPublicKeyRing(publicKeyRingEncoded, new JcaKeyFingerprintCalculator());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * 
	 * @return true if secret key ring is set, otherwise false
	 */
	public boolean hasPrivateKey() {
		return secretKeyRing != null;
	}

	/**
	 * 
	 * @return true if public key ring is set, otherwise false
	 */
	public boolean hasPublicKey() {
		return publicKeyRing != null;
	}

	/**
	 * 
	 * @return secret key ring
	 */
	public PGPSecretKeyRing getSecretKeyRing() {
		return secretKeyRing;
	}

	/**
	 * 
	 * @return public key ring
	 */
	public PGPPublicKeyRing getPublicKeyRing() {
		return publicKeyRing;
	}

	/**
	 * 
	 * @return users email
	 */
	public String getEmail() {
		if (publicKeyRing != null) {
			return publicKeyRing.getPublicKey().getUserIDs().next();
		} else {
			return secretKeyRing.getSecretKey().getUserIDs().next();
		}
	}

	/**
	 * 
	 * @return algorithm number
	 */
	public int getAlgorithmNumber() {
		if (publicKeyRing != null) {
			return publicKeyRing.getPublicKey().getAlgorithm();
		} else {
			return secretKeyRing.getPublicKey().getAlgorithm();
		}
	}

	/**
	 * 
	 * @return strength of bits
	 */
	public int getBitStrength() {
		if (publicKeyRing != null) {
			return publicKeyRing.getPublicKey().getBitStrength();
		} else {
			return secretKeyRing.getPublicKey().getBitStrength();
		}
	}

	/**
	 * 
	 * @return expiration date
	 */
	public Date getValidFrom() {
		if (publicKeyRing != null) {
			return publicKeyRing.getPublicKey().getPublicKeyPacket().getTime();
		} else {
			return secretKeyRing.getPublicKey().getPublicKeyPacket().getTime();
		}
	}

	/**
	 * 
	 * @return key ID
	 */
	public long getKeyId() {
		if (secretKeyRing != null) {
			return secretKeyRing.getSecretKey().getKeyID();
		} else {
			return publicKeyRing.getPublicKey().getKeyID();
		}
	}

	/**
	 * 
	 * @return type of key
	 */
	public KEYRINGTYPE getKeyRingType() {
		if (secretKeyRing == null)
			return KEYRINGTYPE.PUBLIC;
		else if (publicKeyRing == null)
			return KEYRINGTYPE.SECRET;
		else
			return KEYRINGTYPE.PUBLIC_SECRET;
	}

	/**
	 * Exports secret/public key ring to file provided
	 * 
	 * @param fileName          destination file for storing key ring
	 * @param wantPublicKeyRing true if exporting secret ring, otherwise ture
	 */
	public void exportKeyRing(File fileName, boolean wantPublicKeyRing) {
		if (wantPublicKeyRing)
			exportPublicKeyRing(fileName);
		else
			exportSecretKeyRing(fileName);
	}

	private void exportSecretKeyRing(File fileName) {
		assert (secretKeyRing != null);

		try {
			ArmoredOutputStream privateOut = new ArmoredOutputStream(
					new BufferedOutputStream(new FileOutputStream(fileName)));
			secretKeyRing.encode(privateOut);
			privateOut.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void exportPublicKeyRing(File fileName) {
		assert (publicKeyRing != null);

		try {
			ArmoredOutputStream privateOut = new ArmoredOutputStream(
					new BufferedOutputStream(new FileOutputStream(fileName)));
			publicKeyRing.encode(privateOut);
			privateOut.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
