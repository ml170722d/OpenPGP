package etf.openpgp.za170657d_ml170722d.security;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Stream;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

public class KeyManager3 {

	public static PGPPublicKeyRingCollection publicKeyRingCollection;
	public static PGPSecretKeyRingCollection secretKeyRingCollection;

	public static PGPPublicKey readPublicKeyFromFile(String filePath) throws IOException, PGPException {
		try (InputStream inputStream = new BufferedInputStream(new FileInputStream(filePath))) {
			PGPPublicKeyRingCollection pgpPublicKeyRingCollection = new PGPPublicKeyRingCollection(
					PGPUtil.getDecoderStream(inputStream), new JcaKeyFingerprintCalculator());
			Iterator keyRingIterator = pgpPublicKeyRingCollection.getKeyRings();
			while (keyRingIterator.hasNext()) {
				PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIterator.next();
				Iterator keyIterator = keyRing.getPublicKeys();
				while (keyIterator.hasNext()) {
					PGPPublicKey key = (PGPPublicKey) keyIterator.next();
					if (key.isEncryptionKey()) {
						return key;
					}
				}
			}
		}
		throw new IllegalArgumentException("Can't find encryption key in key ring.");
	}

	public static PGPSecretKey readSecretKeyFromFile(String filePath) throws IOException, PGPException {
		InputStream input = new BufferedInputStream(new FileInputStream(filePath));
		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input),
				new JcaKeyFingerprintCalculator());

		Iterator keyRingIter = pgpSec.getKeyRings();
		while (keyRingIter.hasNext()) {
			PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();

			Iterator keyIter = keyRing.getSecretKeys();
			while (keyIter.hasNext()) {
				PGPSecretKey key = (PGPSecretKey) keyIter.next();

				if (key.isSigningKey()) {
					return key;
				}
			}
		}

		throw new IllegalArgumentException("Can't find signing key in key ring.");
	}

	public static void initPublicKeysRing() {

		try {

			List<PGPPublicKeyRing> clctn = new ArrayList<>();
			try (Stream<Path> paths = Files.walk(Paths.get("publickeys"))) {
				paths.filter(Files::isRegularFile).forEach((file) -> {
					InputStream inputStream;
					try {
						inputStream = new BufferedInputStream(
								new FileInputStream("publickeys/" + file.getFileName().toString()));
						clctn.add(new PGPPublicKeyRing(PGPUtil.getDecoderStream(inputStream),
								new JcaKeyFingerprintCalculator()));
					} catch (FileNotFoundException ex) {
						Logger.getLogger(KeyManager3.class.getName()).log(Level.SEVERE, null, ex);
					} catch (IOException ex) {
						Logger.getLogger(KeyManager3.class.getName()).log(Level.SEVERE, null, ex);
					}
				});
			}

			KeyManager3.publicKeyRingCollection = new PGPPublicKeyRingCollection(clctn);

		} catch (PGPException | IOException ex) {
			Logger.getLogger(KeyManager3.class.getName()).log(Level.SEVERE, null, ex);
		}
	}

	public static void initSecretKeysRing() {

		try {

			List<PGPSecretKeyRing> clctn = new ArrayList<>();
			try (Stream<Path> paths = Files.walk(Paths.get("secretkeys"))) {
				paths.filter(Files::isRegularFile).forEach((file) -> {
					InputStream inputStream;
					try {
						inputStream = new BufferedInputStream(
								new FileInputStream("secretkeys/" + file.getFileName().toString()));
						clctn.add(new PGPSecretKeyRing(PGPUtil.getDecoderStream(inputStream),
								new JcaKeyFingerprintCalculator()));
					} catch (FileNotFoundException ex) {
						Logger.getLogger(KeyManager3.class.getName()).log(Level.SEVERE, null, ex);
					} catch (IOException ex) {
						Logger.getLogger(KeyManager3.class.getName()).log(Level.SEVERE, null, ex);
					} catch (PGPException ex) {
						Logger.getLogger(KeyManager.class.getName()).log(Level.SEVERE, null, ex);
					}
				});
			}

			KeyManager3.secretKeyRingCollection = new PGPSecretKeyRingCollection(clctn);

		} catch (FileNotFoundException ex) {
			Logger.getLogger(KeyManager3.class.getName()).log(Level.SEVERE, null, ex);
		} catch (IOException ex) {
			Logger.getLogger(KeyManager3.class.getName()).log(Level.SEVERE, null, ex);
		} catch (PGPException ex) {
			Logger.getLogger(KeyManager.class.getName()).log(Level.SEVERE, null, ex);
		}
	}

	static PGPPrivateKey findPrivateKey(long keyID, char[] pass) throws PGPException, NoSuchProviderException {
		PGPSecretKey pgpSecKey = secretKeyRingCollection.getSecretKey(keyID);

		if (pgpSecKey == null) {
			return null;
		}

		return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
	}
}
