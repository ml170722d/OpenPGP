package etf.openpgp.za170657d_ml170722d.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import etf.openpgp.za170657d_ml170722d.security.KeyRing;
import etf.openpgp.za170657d_ml170722d.security.error.InvalidExportType;
import etf.openpgp.za170657d_ml170722d.security.error.InvalidStorage;

public class KeyManage {

	public static enum KeyType {
		PUBLIC, PRIVATE
	}

	private String storageFile;
	private List<KeyRing> keyRingList;

	private static KeyManage instance = null;

	private KeyManage(String storageFilePath) {
		File storage = new File(storageFilePath);

		try {
			if (!storage.exists())
				storage.createNewFile();

			this.storageFile = storageFilePath;
			this.keyRingList = new ArrayList<>();
		} catch (IOException e) {
			e.printStackTrace();
		}
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
	 * Returns instance of KeyManage class.
	 * 
	 * @param storage path to storage file
	 * @return KeyStorace class instance
	 * @throws InvalidStorage if storage path for instance was not provided
	 */
	public static KeyManage getInstance(String storagePath) throws InvalidStorage {

		if (!Files.exists(Paths.get(storagePath)))
			throw new InvalidStorage();

		if (instance == null)
			instance = new KeyManage(storagePath);
		return instance;
	}

	/**
	 * Returns instance of KeyManage class. Uses default storage path.
	 * 
	 * @return KeyStorace class instance
	 */
	public static KeyManage getInstance() {
		String basePath = new File("").getAbsolutePath();

		try {
			return getInstance(basePath + "\\keyPair\\OpenPGPApp.data");
		} catch (InvalidStorage e) {
			e.printStackTrace();
		}

		return null;
	}

	/*------------------------------------------------------------------------------------------------*/
	/*
	 * public methods
	 */

	/**
	 * Returns true of operation was successful, otherwise false
	 * 
	 * @return boolean
	 */
	@SuppressWarnings("unchecked")
	public boolean loadKeyRings() {
		try {
			File secretFile = new File(storageFile);
			if (secretFile.exists()) {
				ObjectInputStream in = new ObjectInputStream(new FileInputStream(secretFile));
				List<byte[]> encodedKeyRingList = (List<byte[]>) in.readObject();

				for (int i = 0; i < encodedKeyRingList.size(); i += 2) {
					keyRingList.add(new KeyRing(encodedKeyRingList.get(i), encodedKeyRingList.get(i + 1)));
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
	 * @return boolean
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
	 * @return boolean
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
		} catch (InvalidExportType e) {
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

	/*------------------------------------------------------------------------------------------------*/
	/*
	 * private methods
	 */

	private KeyPair generateJavaRSAKeyPair(RSAUtil.KeySize size) throws GeneralSecurityException {
		return RSAUtil.generateKeyPair(size);
	}

	private JcaPGPKeyPair generateOpenPGPKeyPair(KeyPair rsaKP, int algNum) throws PGPException {
		return new JcaPGPKeyPair(algNum, rsaKP, new Date());
	}

	private void generateKeyPairSign(char[] password, String email, PGPKeyPair openPGPKeyPair) throws PGPException {

		PGPDigestCalculator calcSHAx = new JcaPGPDigestCalculatorProviderBuilder().build()
				.get(HashAlgorithmTags.SHA256);

		PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, openPGPKeyPair,
				email, calcSHAx, null, null,
				new JcaPGPContentSignerBuilder(openPGPKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA512),
				new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, calcSHAx).setProvider("BC")
						.build(password));

		keyRingList.add(new KeyRing(keyRingGen.generateSecretKeyRing(), keyRingGen.generatePublicKeyRing()));
	}

	private void generateKeyPairEncryption(char[] password, String email, PGPKeyPair openPGPKeyPairRSASign,
			PGPKeyPair openPgpKeyPairRSAEncryption) throws PGPException {

		PGPDigestCalculator calcSHAx = new JcaPGPDigestCalculatorProviderBuilder().build()
				.get(HashAlgorithmTags.SHA256);

		PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION,
				openPGPKeyPairRSASign, email, calcSHAx, null, null,
				new JcaPGPContentSignerBuilder(openPGPKeyPairRSASign.getPublicKey().getAlgorithm(),
						HashAlgorithmTags.SHA512),
				new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, calcSHAx).setProvider("BC")
						.build(password));

		keyRingGen.addSubKey(openPgpKeyPairRSAEncryption);

		keyRingList.add(new KeyRing(keyRingGen.generateSecretKeyRing(), keyRingGen.generatePublicKeyRing()));
	}

}
