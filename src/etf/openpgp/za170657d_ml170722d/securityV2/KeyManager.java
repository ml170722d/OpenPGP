package etf.openpgp.za170657d_ml170722d.securityV2;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import etf.openpgp.za170657d_ml170722d.security.error.AlreadyInUse;
import etf.openpgp.za170657d_ml170722d.security.error.InvalidType;
import etf.openpgp.za170657d_ml170722d.securityV2.KeyRing.KeyRingTags;
import etf.openpgp.za170657d_ml170722d.securityV2.RSAUtil.KeySizeTags;

public class KeyManager {
	private static String storagePath = new File("").getAbsolutePath() + "/data/OpenPGP.dat";
	private static String exportPath = new File("").getAbsolutePath() + "/keys/";
	private static Provider provider = new BouncyCastleProvider();

	public static void init() {
		if (Security.getProvider("BC") == null)
			Security.addProvider(provider);
	}

	public static void storeKeyChain() {
		try {
			List<byte[]> encodedKeyRings = new ArrayList<byte[]>();

			for (KeyRing kr : KeyChain.getChain()) {
				encodedKeyRings.addAll(kr.getEncodedKeyRings());
			}

			ObjectOutputStream storage = new ObjectOutputStream(new FileOutputStream(storagePath));
			storage.writeObject(encodedKeyRings);

			storage.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@SuppressWarnings("unchecked")
	public static void loadKeyChain() {
		try {
			if (Files.exists(Paths.get(storagePath))) {
				ObjectInputStream in = new ObjectInputStream(new FileInputStream(storagePath));
				List<byte[]> encodedKeyRings = (List<byte[]>) in.readObject();

				for (int i = 0; i < encodedKeyRings.size(); i += 2) {
					KeyChain.add(new KeyRing(encodedKeyRings.get(i), encodedKeyRings.get(i + 1)));
				}

				in.close();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		System.out.println("Number of keys loaded: " + KeyChain.getChain().size());
	}

	public static void deleteKey(int index, int type) throws Exception {
		KeyRing kr = KeyChain.getKeyRing(index);
		kr.removeKeyRing(type);
		if (!kr.hasPrivateKey() && !kr.hasPublicKey())
			KeyChain.getChain().remove(kr);
	}

	public static void deleteKey(long keyId, int type) throws InvalidType, Exception {
		KeyRing kr = KeyChain.getKeyRing(keyId);
		kr.removeKeyRing(type);
		if (!kr.hasPrivateKey() && !kr.hasPublicKey())
			KeyChain.getChain().remove(kr);
	}

	public static void deleteKey(byte[] fingerprint, int type) throws InvalidType, Exception {
		KeyRing kr = KeyChain.getKeyRing(fingerprint);
		kr.removeKeyRing(type);
		if (!kr.hasPrivateKey() && !kr.hasPublicKey())
			KeyChain.getChain().remove(kr);
	}

	public static void exportKey(int index, int type, String fileName) throws InvalidType, IOException {
		KeyChain.getKeyRing(index).exportKeyRing(exportPath, fileName, type);
	}

	public static void exportKey(long keyId, int type, String fileName) throws InvalidType, IOException, Exception {
		KeyChain.getKeyRing(keyId).exportKeyRing(exportPath, fileName, type);
	}

	public static void exportKey(byte[] fingerprint, int type, String fileName)
			throws InvalidType, IOException, Exception {
		KeyChain.getKeyRing(fingerprint).exportKeyRing(exportPath, fileName, type);
	}

	private static KeyPair generateJavaRSAKeyPair(int size) throws NoSuchAlgorithmException {
		return RSAUtil.generateRSAKeyPari(size, provider);
	}

	private static JcaPGPKeyPair generateOpenPGPKeyPair(KeyPair keyPair, int algorythm) throws PGPException {
		return new JcaPGPKeyPair(algorythm, keyPair, new Date());
	}

	private static KeyRing generateKeyRing(char[] password, String userId, PGPKeyPair pgpKeyPair) throws PGPException {
		PGPDigestCalculator sha1calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

		PGPKeyRingGenerator keyRingGenerator = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, pgpKeyPair,
				userId, sha1calc, null, null,
				new JcaPGPContentSignerBuilder(pgpKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
				new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1calc).setProvider(provider)
						.build(password));

		return new KeyRing(keyRingGenerator.generatePublicKeyRing(), keyRingGenerator.generateSecretKeyRing());
	}

	private static void generatePublicKeyRingFromInputStream(InputStream in)
			throws IOException, PGPException, AlreadyInUse {
		in = PGPUtil.getDecoderStream(in);

		PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in, new JcaKeyFingerprintCalculator());
		Iterator<PGPPublicKeyRing> it = pgpPub.getKeyRings();

		while (it.hasNext()) {
			PGPPublicKeyRing pubKR = it.next();
			KeyChain.add(new KeyRing(pubKR));
		}
	}

	private static void generateSecretKeyRingFromInputStream(InputStream in)
			throws IOException, PGPException, AlreadyInUse {
		in = PGPUtil.getDecoderStream(in);

		PGPSecretKeyRingCollection pgpPriv = new PGPSecretKeyRingCollection(in, new JcaKeyFingerprintCalculator());
		Iterator<PGPSecretKeyRing> it = pgpPriv.getKeyRings();

		while (it.hasNext()) {
			PGPSecretKeyRing privKR = it.next();
			KeyChain.add(new KeyRing(privKR));
		}
	}

	protected static void importPublicKeyRingFromFile(String fileName)
			throws FileNotFoundException, IOException, PGPException, AlreadyInUse {
		ArmoredInputStream in = new ArmoredInputStream(new BufferedInputStream(new FileInputStream(fileName)));
		generatePublicKeyRingFromInputStream(in);
	}

	protected static void importSecretKeyRingFromFile(String fileName)
			throws FileNotFoundException, IOException, PGPException, AlreadyInUse {
		ArmoredInputStream in = new ArmoredInputStream(new BufferedInputStream(new FileInputStream(fileName)));
		generateSecretKeyRingFromInputStream(in);
	}

	public static boolean importKeyRingFromFile(String fileName) throws AlreadyInUse {
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

	public static void generateRSAKeyPair(char[] password, String userId, int size)
			throws NoSuchAlgorithmException, PGPException, AlreadyInUse {
		KeyPair javaRSAkp = generateJavaRSAKeyPair(size);
		PGPKeyPair pgpRSAkp = generateOpenPGPKeyPair(javaRSAkp, PGPPublicKey.RSA_GENERAL);

		KeyRing kr = generateKeyRing(password, userId, pgpRSAkp);
		KeyChain.add(kr);
	}

	public static void main(String[] args) throws Exception {
		java.security.Security.setProperty("crypto.policy", "unlimited");
		KeyManager.init();
		{
			KeyManager.loadKeyChain();

			String password[] = { "123", "abc" };
			String userId[] = { "luka<luka>", "aki <aki>" };

			for (int i = 0; i < userId.length; i++) {
				try {
					KeyManager.generateRSAKeyPair(password[i].toCharArray(), userId[i], KeySizeTags._1024b);
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (PGPException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (AlreadyInUse e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}

			for (int i = 0; i < KeyChain.getChain().size(); i++) {
				KeyManager.exportKey(i, KeyRingTags.PUBLIC, "pub" + i);
				KeyManager.exportKey(i, KeyRingTags.PRIVATE, "priv" + i);
			}

			System.out.println(KeyChain.getChain().size());

			KeyManager.storeKeyChain();
		}

//		{
//			try {
//				KeyManager.importKeyRingFromFile(
//						"D:\\etf online\\zp\\projekat\\OpenPGP\\keys\\public\\496935046168542089.asc");
//			} catch (AlreadyInUse e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}
//			System.out.println(KeyChain.getChain().size());
//		}
//
//		{
//			System.out.println(KeyChain.getKeyRing(0).getUserId());
//			System.out.println(KeyChain.getKeyRing(1).getUserId());
//			System.out.println(KeyChain.getChain().size());
//			KeyManager.deleteKey(0, KeyRingTags.PUBLIC);
//			KeyManager.deleteKey(1, KeyRingTags.PRIVATE);
//			KeyManager.deleteKey(0, KeyRingTags.PRIVATE);
//			System.out.println(KeyChain.getChain().size());
//		}
	}
}
