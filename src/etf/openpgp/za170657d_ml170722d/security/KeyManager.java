package etf.openpgp.za170657d_ml170722d.security;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import etf.openpgp.za170657d_ml170722d.GUI.UserInfo;
import etf.openpgp.za170657d_ml170722d.security.KeyRing;
import etf.openpgp.za170657d_ml170722d.security.error.InvalidStorage;

public class KeyManager {

	public static enum KeyType {
		PUBLIC, PRIVATE
	}

	private String storageFile;
	public List<KeyRing> keyRingList;

	private static KeyManager instance = null;

	private KeyManager(String storageFilePath) throws IOException {
		File storage = new File(storageFilePath);

		if (!storage.exists())
			storage.createNewFile();

		this.storageFile = storageFilePath;
		this.keyRingList = new ArrayList<>();

	}

	/*------------------------------------------------------------------------------------------------*/
	/*
	 * public static methods
	 */

	/**
	 * 
	 * @param secretKey key used to extract data
	 * @return expiration date for key provided
	 */
	public static Date getValidFromSecretKey(PGPSecretKey secretKey) {
		Date validFrom = secretKey.getPublicKey().getPublicKeyPacket().getTime();
		return validFrom;
	}

	/**
	 * 
	 * @param secretKey key used to extract data
	 * @return email for key provided
	 */
	public static String getEmailFromSecretKey(PGPSecretKey secretKey) {
		Iterator<String> userIDs = secretKey.getUserIDs();
		return userIDs.next();
	}

	/**
	 * 
	 * @param secretKey key use to extract private key
	 * @param password  password of key provided
	 * @return extracted private key
	 * @throws PGPException if password was invalid
	 */
	public static PGPPrivateKey getPrivateKeyFromSecretKey(PGPSecretKey secretKey, char[] password)
			throws PGPException {
		PGPPrivateKey privateKey = secretKey.extractPrivateKey(
				new JcePBESecretKeyDecryptorBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(password));

		return privateKey;
	}

	/**
	 * 
	 * @param secretKey key to check
	 * @param password  password of key
	 * @return true if correct, otherwise false
	 */
	public static boolean isPasswordForSecretKey(PGPSecretKey secretKey, char[] password) {
		try {
			getPrivateKeyFromSecretKey(secretKey, password);
			return true;
		} catch (PGPException e) {
			return false;
		}
	}

	/**
	 * Returns instance of KeyManagerr class.
	 * 
	 * @param storage path to storage file
	 * @return KeyStorace class instance
	 * @throws InvalidStorage if storage path for instance was not provided
	 * @throws IOException
	 */
	protected static KeyManager getInstance(String storagePath) throws IOException {

		File file = new File(storagePath);
		if (!file.exists())
			file.createNewFile();

		if (instance == null)
			instance = new KeyManager(storagePath);
		return instance;
	}

	/**
	 * Returns instance of KeyManager class. Uses default storage path.
	 * 
	 * @return KeyStorace class instance
	 */
	public static KeyManager getInstance() {
		String basePath = new File("").getAbsolutePath();

		try {
			return getInstance(basePath + "\\keyPair\\OpenPGP.ses");
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}

	/**
	 * Return public key from key ring passed
	 * 
	 * @param pubKR key ring needed to extract public key
	 * @return public key for ring
	 */
	public static PGPPublicKey getRSAEncryptionPublicKeyFromKeyRing(PGPPublicKeyRing pubKR) {
		PGPPublicKey RSAkey = null;

		Iterator<PGPPublicKey> itKey = pubKR.getPublicKeys();

		while (itKey.hasNext()) {
			PGPPublicKey key = itKey.next();

			if (key.isEncryptionKey()) {
				RSAkey = key;
				break;
			}
		}

		return RSAkey;
	}

	/*------------------------------------------------------------------------------------------------*/
	/*
	 * public methods
	 */

	/**
	 * Returns true of operation was successful, otherwise false
	 * 
	 * @return true on success, otherwise false
	 * @throws PGPException as constructor {@link KeyRing} class
	 */
	@SuppressWarnings("unchecked")
	public boolean loadKeyRings() throws PGPException {
		try {
			File secretFile = new File(storageFile);
			if (secretFile.exists()) {

				ObjectInputStream in = new ObjectInputStream(new FileInputStream(secretFile));
				List<byte[]> encodedKeyRingList = (List<byte[]>) in.readObject();

				for (int i = 0; i < encodedKeyRingList.size(); i += 2) {
					keyRingList.add(new KeyRing(encodedKeyRingList.get(i + 1), encodedKeyRingList.get(i)));
				}

				in.close();
			}
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
			return false;
		}
		System.out.println("Number of keys loaded: " + keyRingList.size());
		return true;
	}

	/**
	 * Returns true of operation was successful, otherwise false
	 * 
	 * @return true on success, otherwise false
	 */
	public boolean storeKeyRings() {
		try {
			List<byte[]> encodedKeyRings = new ArrayList<>();

			for (KeyRing keyRing : keyRingList) {
				encodedKeyRings.addAll(keyRing.getEncodedKeyRings());
			}

			ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(storageFile));
			out.writeObject(encodedKeyRings);

			out.close();
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}

		return true;
	}

	/**
	 * Returns true if operation was successful, otherwise false
	 * 
	 * @param index    index of key to export
	 * @param fileName name of export file
	 * @param type     type of file to export
	 * @return true on success, otherwise false
	 */
	public boolean exportKey(int index, File fileName, KeyType type) {
		try {
			switch (type) {
			case PRIVATE:
				keyRingList.get(index).exportKeyRing(fileName, KeyRing.KeyRingType.SECRET);
				break;
			case PUBLIC:
				keyRingList.get(index).exportKeyRing(fileName, KeyRing.KeyRingType.PUBLIC);
				break;
			default:
				break;
			}
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	/**
	 * 
	 * @param ind index of key
	 * @return true if private, otherwise false
	 */
	public boolean isKeyPrivate(int ind) {
		return keyRingList.get(ind).hasPrivateKey();
	}

	/**
	 * Returns list of pgp secret keys
	 * 
	 * @return list of pgp secret keys
	 */
	public List<PGPSecretKeyRing> getAllSecretKeyRings() {
		return keyRingList.stream().filter(KeyRing::hasPrivateKey).map(KeyRing::getSecretKeyRing)
				.collect(Collectors.toList());
	}

	/**
	 * Removes key from list if password was correct
	 * 
	 * @param ind      index of key
	 * @param password password for key
	 * @return true if successful, otherwise false
	 */
	public boolean deleteKey(int ind, char[] password) {
		KeyRing keyRing = keyRingList.get(ind);

		if (keyRing.hasPrivateKey()) {
			if (isPasswordForSecretKey(keyRing.getSecretKeyRing().getSecretKey(), password)) {
				keyRingList.remove(ind);
				return true;
			} else {
				return false;
			}
		} else {
			keyRingList.remove(ind);
			return true;
		}
	}

	/**
	 * Creates new pair of keys for signature
	 * 
	 * @param password encryption password
	 * @param email    email of key pair
	 * @param size     size of key pair
	 * @throws GeneralSecurityException if a KeyPairGeneratorSpi implementation for
	 *                                  the specified algorithm is not available
	 *                                  from the specified provider
	 * @throws PGPException             if conversion fails.
	 */
	public void generateRSAKeyPairSign(char[] password, String email, RSAUtil.KeySize size)
			throws GeneralSecurityException, PGPException {
		KeyPair javaRSAkp = generateJavaRSAKeyPair(size);
		PGPKeyPair openPGPkp = generateOpenPGPKeyPair(javaRSAkp, PGPPublicKey.RSA_SIGN);

		generateKeyPairSign(password, email, openPGPkp);
	}

	/**
	 * Creates new pair of keys for signature
	 * 
	 * @param password encryption password
	 * @param email    email of key pair
	 * @param size     size of key pair
	 * @throws GeneralSecurityException if a KeyPairGeneratorSpi implementation for
	 *                                  the specified algorithm is not available
	 *                                  from the specified provider
	 * @throws PGPException             if conversion fails.
	 */
	public void generateRSAKeyPairEncryption(char[] password, String email, RSAUtil.KeySize signSize,
			RSAUtil.KeySize encrSize) throws GeneralSecurityException, PGPException {
		KeyPair javaRSAkpSign = generateJavaRSAKeyPair(signSize);
		PGPKeyPair openpPGPkpSign = generateOpenPGPKeyPair(javaRSAkpSign, PGPPublicKey.RSA_SIGN);

		KeyPair javaRSAkpEncr = generateJavaRSAKeyPair(encrSize);
		PGPKeyPair openPGPkpEncr = generateOpenPGPKeyPair(javaRSAkpEncr, PGPPublicKey.RSA_ENCRYPT);

		generateKeyPairEncryption(password, email, openpPGPkpSign, openPGPkpEncr);
	}

	/**
	 * Imports public key ring from file provided
	 * 
	 * @param fileName file used to import
	 * @throws FileNotFoundException if the file does not exist,is a directory
	 *                               rather than a regular file,or for some other
	 *                               reason cannot be opened for reading.
	 * @throws IOException
	 * @throws PGPException          if an object is encountered which isn't a
	 *                               PGPPublicKeyRing
	 */
	public void importPublicKeyRingFromFile(String fileName) throws FileNotFoundException, IOException, PGPException {
		ArmoredInputStream in = new ArmoredInputStream(new BufferedInputStream(new FileInputStream(fileName)));
		generatePublicKeyRingFromInputStream(in);
	}

	/**
	 * Imports secret key ring from file provided
	 * 
	 * @param fileName file used to import
	 * @throws FileNotFoundException if the file does not exist,is a directory
	 *                               rather than a regular file,or for some other
	 *                               reason cannot be opened for reading.
	 * @throws IOException
	 * @throws PGPException          if an object is encountered which isn't a
	 *                               PGPSecretKeyRing
	 */
	public void importSecretKeyRingFromFile(String fileName) throws FileNotFoundException, IOException, PGPException {
		ArmoredInputStream in = new ArmoredInputStream(new BufferedInputStream(new FileInputStream(fileName)));
		generateSecretKeyRingFromInputStream(in);
	}

	/**
	 * Tries to import public/secret key ring from file
	 * 
	 * @param fileName file used to import
	 * @return true if successfully imported, otherwise false
	 */
	public boolean importKeyRingFromFile(String fileName) {
		try {
			ArmoredInputStream in = new ArmoredInputStream(new BufferedInputStream(new FileInputStream(fileName)));
			generatePublicKeyRingFromInputStream(in);

			return true;
		} catch (IOException | PGPException e) {
		}

		try {
			ArmoredInputStream in = new ArmoredInputStream(new BufferedInputStream(new FileInputStream(fileName)));
			generateSecretKeyRingFromInputStream(in);
			return true;
		} catch (IOException | PGPException e) {
		}

		return false;
	}

	public List<UserInfo> getUIUserInfo() {
		List<UserInfo> uiList = new ArrayList<>();

		int i = 0;
		for (KeyRing kr : keyRingList) {
			long keyId;
			try {
				keyId = kr.getPublicKeyRing().getPublicKey().getKeyID();
			} catch (Exception e) {
				keyId = kr.getSecretKeyRing().getPublicKey().getKeyID();
			}
			uiList.add(new UserInfo(i++, kr.getEmail(), kr.getValidFrom(), keyId));
		}

		return uiList;
	}

	public KeyRing getKeyRing(int index) {
		return keyRingList.get(index);
	}
	
	/*------------------------------------------------------------------------------------------------*/
	/*
	 * private methods
	 */

	private KeyPair generateJavaRSAKeyPair(RSAUtil.KeySize size) throws GeneralSecurityException {
		return RSAUtil.generateRSAKeyPair(size);
	}

	private JcaPGPKeyPair generateOpenPGPKeyPair(KeyPair rsaKP, int algNum) throws PGPException {
		return new JcaPGPKeyPair(algNum, rsaKP, new Date());
	}

	private void generateKeyPairSign(char[] password, String email, PGPKeyPair openPGPKeyPair) throws PGPException {

		PGPDigestCalculator calcSHAx = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

		PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, openPGPKeyPair,
				email, calcSHAx, null, null,
				new JcaPGPContentSignerBuilder(openPGPKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA512),
				new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, calcSHAx).setProvider("BC")
						.build(password));

		keyRingList.add(new KeyRing(keyRingGen.generateSecretKeyRing(), keyRingGen.generatePublicKeyRing()));
	}

	private void generateKeyPairEncryption(char[] password, String email, PGPKeyPair openPGPKeyPairRSASign,
			PGPKeyPair openPgpKeyPairRSAEncryption) throws PGPException {

		PGPDigestCalculator calcSHAx = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

		PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION,
				openPGPKeyPairRSASign, email, calcSHAx, null, null,
				new JcaPGPContentSignerBuilder(openPGPKeyPairRSASign.getPublicKey().getAlgorithm(),
						HashAlgorithmTags.SHA512),
				new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, calcSHAx).setProvider("BC")
						.build(password));

		keyRingGen.addSubKey(openPgpKeyPairRSAEncryption);

		keyRingList.add(new KeyRing(keyRingGen.generateSecretKeyRing(), keyRingGen.generatePublicKeyRing()));
	}

	private void generatePublicKeyRingFromInputStream(InputStream in) throws IOException, PGPException {
		in = PGPUtil.getDecoderStream(in);

		PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in, new JcaKeyFingerprintCalculator());
		Iterator<PGPPublicKeyRing> it = pgpPub.getKeyRings();

		while (it.hasNext()) {
			PGPPublicKeyRing pubKR = it.next();
			keyRingList.add(new KeyRing(pubKR));
		}

	}

	private void generateSecretKeyRingFromInputStream(InputStream in) throws IOException, PGPException {
		in = PGPUtil.getDecoderStream(in);

		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(in, new JcaKeyFingerprintCalculator());
		Iterator<PGPSecretKeyRing> it = pgpSec.getKeyRings();

		while (it.hasNext()) {
			PGPSecretKeyRing secKR = it.next();
			keyRingList.add(new KeyRing(secKR));
		}
	}

	/*------------------------------------------------------------------------------------------------*/
	/*
	 * test methods
	 */
	public static void testGenerateExportAndImportKeys() {
		try {
			java.security.Security.addProvider(new BouncyCastleProvider());
			java.security.Security.setProperty("crypto.policy", "unlimited");

			{
				/*
				 * data needed
				 */
				char[] password = "password".toCharArray();
				String email = "a@gmail.com";
				String email1 = "b@gmail.com";
				String email2 = "c@gmail.com";

				String pubName = new File("").getAbsoluteFile() + "\\keyPair\\test\\pub.asc";
				String privName = new File("").getAbsoluteFile() + "\\keyPair\\test\\priv.asc";

				/*
				 * generate key ring
				 */
				KeyManager km = KeyManager.getInstance();
				km.generateRSAKeyPairSign(password, email, RSAUtil.KeySize._1024b);
				km.generateRSAKeyPairSign(password, email1, RSAUtil.KeySize._1024b);
				km.generateRSAKeyPairSign(password, email2, RSAUtil.KeySize._1024b);

				/*
				 * export keys separately (adding 2 new keys to list)
				 */
				km.exportKey(0, new File(pubName), KeyType.PUBLIC);
				km.exportKey(0, new File(privName), KeyType.PRIVATE);

				/*
				 * import keys separately
				 */
				km.importPublicKeyRingFromFile(pubName);
				km.importSecretKeyRingFromFile(privName);

				System.out.println(km.keyRingList.size());

				/*
				 * print use data
				 */
				List<UserInfo> list = km.getUIUserInfo();
				System.out.println(list);
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void testGenerateStoreAndLoadKeys() {
		try {
			/*
			 * data needed
			 */
			char[] password = "password".toCharArray();
			String email1 = "a@gmail.com";
			String email2 = "b@gmail.com";

			/*
			 * generate key ring
			 */
			KeyManager km = KeyManager.getInstance();
			km.generateRSAKeyPairSign(password, email1, RSAUtil.KeySize._1024b);
			km.generateRSAKeyPairSign(password, email2, RSAUtil.KeySize._1024b);

//			km.generateRSAKeyPairSign(password, email1, RSAUtil.KeySize._2048b);
//			km.generateRSAKeyPairSign(password, email2, RSAUtil.KeySize._2048b);
//
//			km.generateRSAKeyPairSign(password, email1, RSAUtil.KeySize._4096b);
//			km.generateRSAKeyPairSign(password, email2, RSAUtil.KeySize._4096b);

			/*
			 * store app data to .ses file
			 */
			km.storeKeyRings();

			/*
			 * delete keys in app
			 */
			while (km.keyRingList.size() > 0) {
				km.deleteKey(0, password);
			}

			/*
			 * load app data from .ses file
			 */
			km.loadKeyRings();

			System.out.println(km.keyRingList.size());

			/*
			 * print use data
			 */
			List<UserInfo> list = km.getUIUserInfo();
			System.out.println(list);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		testGenerateExportAndImportKeys();
		testGenerateStoreAndLoadKeys();
	}

}
