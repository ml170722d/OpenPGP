package etf.openpgp.za170657d_ml170722d.securityV2;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import etf.openpgp.za170657d_ml170722d.GUI.EnterPasswordPanel;
import etf.openpgp.za170657d_ml170722d.security.error.InvalidType;

public class KeyRing {

	public static interface KeyRingTags {
		public static int PUBLIC = 1;
		public static int PRIVATE = 2;
	}

	private PGPSecretKeyRing secretKeyRing = null;
	private PGPPublicKeyRing publicKeyRing = null;

	public KeyRing(PGPSecretKeyRing secretKeyRing) {
		this.secretKeyRing = secretKeyRing;
	}

	public KeyRing(PGPPublicKeyRing publicKeyRing) {
		this.publicKeyRing = publicKeyRing;
	}

	public KeyRing(PGPPublicKeyRing publicKeyRing, PGPSecretKeyRing secretKeyRing) {
		this.publicKeyRing = publicKeyRing;
		this.secretKeyRing = secretKeyRing;
	}

	public KeyRing(byte[] publicKeyRingEncoded, byte[] secretKeyRingEncoded) throws IOException, PGPException {
		if (secretKeyRingEncoded.length > 0)
			secretKeyRing = new PGPSecretKeyRing(secretKeyRingEncoded, new JcaKeyFingerprintCalculator());
		if (publicKeyRingEncoded.length > 0)
			publicKeyRing = new PGPPublicKeyRing(publicKeyRingEncoded, new JcaKeyFingerprintCalculator());
	}

	public boolean hasPrivateKey() {
		return secretKeyRing != null;
	}

	public boolean hasPublicKey() {
		return publicKeyRing != null;
	}

	public PGPSecretKeyRing getSecretKeyRing() {
		return secretKeyRing;
	}

	public PGPPublicKeyRing getPublicKeyRing() {
		return publicKeyRing;
	}

	public PGPPublicKey getPublicKey() {
		return publicKeyRing.getPublicKey();
	}

	public PGPSecretKey getSecretKey() {
		return secretKeyRing.getSecretKey();
	}

	public String getUserId() {
		if (publicKeyRing != null) {
			return publicKeyRing.getPublicKey().getUserIDs().next();
		} else {
			return secretKeyRing.getSecretKey().getUserIDs().next();
		}
	}


	public int getAlgorithmNumber() {
		if (publicKeyRing != null) {
			return publicKeyRing.getPublicKey().getAlgorithm();
		} else {
			return secretKeyRing.getPublicKey().getAlgorithm();
		}
	}

	public long getKeyId() {
		if (secretKeyRing != null) {
			return secretKeyRing.getSecretKey().getKeyID();
		} else {
			return publicKeyRing.getPublicKey().getKeyID();
		}
	}

	public byte[] getFingerprint() {
		if (secretKeyRing != null) {
			return secretKeyRing.getPublicKey().getFingerprint();
		} else {
			return publicKeyRing.getPublicKey().getFingerprint();
		}
	}

	public void setPublicKeyRing(PGPPublicKeyRing publicKeyRing) {
		if (this.publicKeyRing != null)
			throw new RuntimeException("Public key ring exists already");

		if (publicKeyRing.getPublicKey().getFingerprint() != this.secretKeyRing.getPublicKey().getFingerprint())
			throw new RuntimeException("Tried to pair up key rings with different fingerprints");

		this.publicKeyRing = publicKeyRing;
	}

	public void setSecretKeyRing(PGPSecretKeyRing secretKeyRing) {
		if (this.secretKeyRing != null)
			throw new RuntimeException("Secret key ring exists already");

		if (secretKeyRing.getPublicKey().getFingerprint() != this.publicKeyRing.getPublicKey().getFingerprint())
			throw new RuntimeException("Tried to pair up key rings with different fingerprints");

		this.secretKeyRing = secretKeyRing;
	}

	public boolean removeKeyRing(int type, char[] password) throws Exception {
		switch (type) {
		case KeyRingTags.PUBLIC:
			this.publicKeyRing = null;
			break;
		case KeyRingTags.PRIVATE:
			if (secretKeyRing == null)
				return false;

			for (int i = 3; i > 0; i--) {
				if (isPasswordForSecretKey(this.secretKeyRing.getSecretKey(), password)) {
					this.secretKeyRing = null;
					return true;
				}
			}

			return false;
		default:
			throw new InvalidType();
		}
		
		return false;
	}

	public Date getCreationDate() {
		if (secretKeyRing != null) {
			return secretKeyRing.getPublicKey().getCreationTime();
		} else {
			return publicKeyRing.getPublicKey().getCreationTime();
		}
	}

	public List<byte[]> getEncodedKeyRings() throws IOException {
		byte[] encodedSecretKeyRing = (secretKeyRing == null) ? new byte[0] : secretKeyRing.getEncoded();
		byte[] encodedPublicKeyRing = (publicKeyRing == null) ? new byte[0] : publicKeyRing.getEncoded();

		return Arrays.asList(encodedPublicKeyRing, encodedSecretKeyRing);
	}

	private void exportPublicKeyRing(File fileName) throws IOException {
		assert (publicKeyRing != null);

		ArmoredOutputStream privateOut = new ArmoredOutputStream(
				new BufferedOutputStream(new FileOutputStream(fileName)));
		publicKeyRing.encode(privateOut);
		privateOut.close();
	}

	private void exportSecretKeyRing(File fileName) throws IOException {
		assert (secretKeyRing != null);

		ArmoredOutputStream privateOut = new ArmoredOutputStream(
				new BufferedOutputStream(new FileOutputStream(fileName)));
		secretKeyRing.encode(privateOut);
		privateOut.close();
	}

	public void exportKeyRing(String filePath, String fileName, int keyType) throws InvalidType, IOException {
		switch (keyType) {
		case KeyRingTags.PUBLIC:
			exportPublicKeyRing(new File(filePath + "public/" + fileName + ".asc"));
			break;
		case KeyRingTags.PRIVATE:
			exportSecretKeyRing(new File(filePath + "secret/" + fileName + ".asc"));
			break;
		default:
			throw new InvalidType();
		}
	}

	public static PGPPrivateKey getPrivateKeyFromSecretKey(PGPSecretKey secretKey, char[] password)
			throws PGPException {
		PGPPrivateKey privateKey = secretKey.extractPrivateKey(
				new JcePBESecretKeyDecryptorBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(password));

		return privateKey;
	}

	public static boolean isPasswordForSecretKey(PGPSecretKey secretKey, char[] password) {
		try {
			getPrivateKeyFromSecretKey(secretKey, password);
			return true;
		} catch (PGPException e) {
			return false;
		}
	}

}
