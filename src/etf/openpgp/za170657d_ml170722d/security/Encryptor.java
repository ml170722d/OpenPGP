package etf.openpgp.za170657d_ml170722d.security;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collector;
import java.util.stream.Collectors;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;

import etf.openpgp.za170657d_ml170722d.security.KeyManager.KeyType;
import etf.openpgp.za170657d_ml170722d.security.KeyRing.KeyRingType;
import etf.openpgp.za170657d_ml170722d.security.RSAUtil.KeySize;
import etf.openpgp.za170657d_ml170722d.security.Signature;
import etf.openpgp.za170657d_ml170722d.security.error.InvalidExportType;

public class Encryptor {

	private static String provider = "BC";

	public static enum EncryptionType {
		REGULAR, ARMORED
	}

	public static enum EncryptionAlg {
		_3DES, CAST5
	}

	/*
	 * private methods
	 */

	private static byte[] encryptCAST5(List<PGPPublicKey> encryptionKeys, byte[] data)
			throws IOException, PGPException {
		PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
				new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.CAST5).setWithIntegrityPacket(true)
						.setSecureRandom(new SecureRandom()).setProvider(provider));

		if (encryptionKeys.isEmpty())
			throw new RuntimeException("Cannot pass 0 encryption keys.");

		for (PGPPublicKey ek : encryptionKeys) {
			encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(ek).setProvider(provider));
		}

		ByteArrayOutputStream encOut = new ByteArrayOutputStream();
		OutputStream cout = encGen.open(encOut, new byte[4096]);

		PGPLiteralDataGenerator ldata = new PGPLiteralDataGenerator();
		OutputStream pout = ldata.open(cout, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, data.length, new Date());
		pout.write(data);

		pout.close();
		cout.close();

		return encOut.toByteArray();
	}

	private static byte[] encrypt3DES(byte[] message, List<PGPPublicKey> publicKeys) throws IOException, PGPException {
		PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
				new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.TRIPLE_DES).setWithIntegrityPacket(true)
						.setSecureRandom(new SecureRandom()).setProvider(provider));

		if (publicKeys.isEmpty())
			throw new RuntimeException("Cannot pass 0 encryption keys.");

		for (PGPPublicKey ek : publicKeys) {
			encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(ek).setProvider(provider));
		}

		ByteArrayOutputStream encOut = new ByteArrayOutputStream();
		OutputStream cout = encGen.open(encOut, new byte[4096]);

		PGPLiteralDataGenerator ldata = new PGPLiteralDataGenerator();
		OutputStream pout = ldata.open(cout, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, message.length, new Date());
		pout.write(message);

		pout.close();
		cout.close();

		return encOut.toByteArray();
	}

	private static byte[] loadDataFromHexFile(String fileName) throws IOException {
		File file = new File(fileName);
		byte[] encryptedData = new byte[(int) file.length()];

		FileInputStream in = new FileInputStream(file);
		in.read(encryptedData);
		in.close();

		return encryptedData;
	}

	private static byte[] loadDataFromArmouredFile(String filename) throws FileNotFoundException, IOException {
		File file = new File(filename);
		byte[] encryptedData = new byte[(int) file.length()];

		ArmoredInputStream in = new ArmoredInputStream(new BufferedInputStream(new FileInputStream(file)));
		in.read(encryptedData);
		in.close();

		return encryptedData;
	}

	private static void writeDataToHexFile(String filename, byte[] data) throws IOException {
		BufferedOutputStream file = new BufferedOutputStream(new FileOutputStream(filename));
		file.write(data);
		file.close();
	}

	private static void writeDataToArmouredFile(String filename, byte[] data) throws IOException {
		ArmoredOutputStream file = new ArmoredOutputStream(new BufferedOutputStream(new FileOutputStream(filename)));
		file.write(data);
		file.close();
	}

	/*------------------------------------------------------------------------------------------------*/
	/*
	 * public methods
	 */

	public static void enctyptDataCAST5(String filename, List<PGPPublicKey> encryptionKeys, byte[] data,
			EncryptionType type) throws IOException {
		OutputStream out;
		switch (type) {
		case REGULAR:
			out = new BufferedOutputStream(new FileOutputStream(filename));
			break;
		case ARMORED:
			out = new ArmoredOutputStream(new BufferedOutputStream(new FileOutputStream(filename)));
			break;
		default:
			throw new RuntimeException("Encryption with CAST5: type passed unknown");
		}

		out.write(data);
		out.close();
	}

	public static void enctyptData3DES(byte[] message, String filename, List<PGPPublicKey> encryptionKeys, byte[] data,
			EncryptionType type) throws IOException, PGPException {
		byte[] encryptedData = encrypt3DES(message, encryptionKeys);

		OutputStream out;
		switch (type) {
		case REGULAR:
			out = new BufferedOutputStream(new FileOutputStream(filename));
			break;
		case ARMORED:
			out = new ArmoredOutputStream(new BufferedOutputStream(new FileOutputStream(filename)));
			break;
		default:
			throw new RuntimeException("Encryption with CAST5: type passed unknown");
		}

		out.write(encryptedData);
		out.close();
	}

	public static PGPPublicKey getEncryptinoKey(PGPPublicKeyRing publicKR) {
		Iterator<PGPPublicKey> itPK = publicKR.getPublicKeys();

		while (itPK.hasNext()) {
			PGPPublicKey pk = itPK.next();
			if (pk.isEncryptionKey())
				return pk;
		}
		return null;
	}

	public static void exportDecryptedDataToFile(byte[] decryptedData, String fileName) {
		try (BufferedOutputStream fileOut = new BufferedOutputStream(new FileOutputStream(fileName))) {
			fileOut.write(decryptedData);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static byte[] readEncryptedDataFromFile(String filename) {
		try {
			byte[] encryptedData = loadDataFromArmouredFile(filename);
			if (!Arrays.equals(encryptedData, new byte[encryptedData.length]))
				return encryptedData;
		} catch (IOException e) {
			System.err.println("INFO: Not an armoured file.");
		}
		try {
			byte[] encryptedData = loadDataFromHexFile(filename);
			return encryptedData;
		} catch (IOException e) {
			System.err.println("INFO: Not a hex file.");
		}

		return null;
	}

	public static byte[] zipBytes(String filename, byte[] input) throws IOException {
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
		OutputStream cos = comData.open(bOut);

		PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();

		OutputStream pOut = lData.open(cos, PGPLiteralData.BINARY, filename, input.length, new Date());

		pOut.write(input);
		pOut.close();

		comData.close();

		return bOut.toByteArray();
	}

	public static byte[] unzipBytes(byte[] data) throws IOException, PGPException {
		ByteArrayInputStream in = new ByteArrayInputStream(data);

		PGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);
		PGPCompressedData object = (PGPCompressedData) pgpFact.nextObject();
		InputStream original = object.getDataStream();

		byte[] literalData = Streams.readAll(original);

		original.close();

		PGPObjectFactory litFact = new JcaPGPObjectFactory(literalData);
		PGPLiteralData litData = (PGPLiteralData) litFact.nextObject();
		byte[] finalData = Streams.readAll(litData.getInputStream());

		return finalData;
	}

	public static EncryptedDataWithSecretKey getSecretKeyForEncryptedData(List<PGPSecretKeyRing> secretKeyRings,
			byte[] pgpEncryptedData) {
		PGPPublicKeyEncryptedData encData = null;
		PGPSecretKey matchingSecretKey = null;

		try {
			PGPObjectFactory pgpFact = new JcaPGPObjectFactory(pgpEncryptedData);
			PGPEncryptedDataList encList = (PGPEncryptedDataList) pgpFact.nextObject();

			for (PGPEncryptedData pgpEnc : encList) {
				PGPPublicKeyEncryptedData pkEnc = (PGPPublicKeyEncryptedData) pgpEnc;

				Optional<PGPSecretKey> curMatchingSecretKey = secretKeyRings.stream()
						.map(secretKeyRing -> secretKeyRing.getSecretKey(pkEnc.getKeyID()))
						.filter(secretKey -> secretKey != null).findFirst();

				if (curMatchingSecretKey.isPresent()) {
					encData = pkEnc;
					matchingSecretKey = curMatchingSecretKey.get();
					break;
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}

		return new EncryptedDataWithSecretKey(encData, matchingSecretKey);
	}

	private static byte[] decryptDataSubStep(PGPPrivateKey privateKey, PGPPublicKeyEncryptedData encData) {
		try {
			PublicKeyDataDecryptorFactory dataDecryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder()
					.setProvider("BC").build(privateKey);

			InputStream clear = encData.getDataStream(dataDecryptorFactory);
			byte[] literalData = Streams.readAll(clear);
			clear.close();

			if (encData.verify()) {
				PGPObjectFactory litFact = new JcaPGPObjectFactory(literalData);
				Object dataObj = litFact.nextObject();

				if (dataObj instanceof PGPLiteralData) {
					return Streams.readAll(((PGPLiteralData) dataObj).getDataStream());
				} else if (dataObj instanceof PGPCompressedData) {
					PGPCompressedData compressedData = (PGPCompressedData) dataObj;
					return Streams.readAll(compressedData.getDataStream());
				} else {
					throw new RuntimeException("Unrecognized data object: " + dataObj.getClass());
				}
			}
		} catch (PGPException | IOException e) {
			e.printStackTrace();
		}

		throw new IllegalStateException("Modification check failed");
	}

	// TODO: check for sinfature
	private static byte[] decryptData(String fileName, char[] password) throws PGPException, IOException {
		byte[] rawData = readEncryptedDataFromFile(fileName);

		EncryptedDataWithSecretKey dataWSK = getSecretKeyForEncryptedData(
				KeyManager.getInstance().getAllSecretKeyRings(), rawData);

		PGPPrivateKey privK = KeyManager.getPrivateKeyFromSecretKey(dataWSK.secretKey, password);
		byte[] originalData = decryptDataSubStep(privK, dataWSK.pbEncryptedData);
		originalData = unzipBytes(originalData);

		List<PGPPublicKey> pubKeys = KeyManager.getInstance().keyRingList.stream().filter(KeyRing::hasPublicKey)
				.map(KeyRing::getPublicKeyRing).map(PGPPublicKeyRing::getPublicKey).collect(Collectors.toList());

		for (PGPPublicKey publicKey : pubKeys) {
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			try {

				boolean isSigned = Signature.verifySignedMessage(publicKey, originalData, bos);

				if (isSigned) {
					originalData = bos.toByteArray();
					break;
				}
			} catch (PGPException e) {
				e.printStackTrace();
			} catch (IOException e) {
//				e.printStackTrace();
			} finally {
				bos.close();
			}
		}

		return originalData;
	}

	public static void encryptData(byte[] message, PGPPrivateKey privateKey, List<PGPPublicKey> publicKeys,
			EncryptionAlg alg, boolean doZip, boolean doRadix64, boolean doSign, boolean doEncrypt,
			String outputFilename) throws PGPException, IOException {

		if (doSign) {
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			PGPSignatureGenerator sGen = new PGPSignatureGenerator(
					new JcaPGPContentSignerBuilder(privateKey.getPublicKeyPacket().getAlgorithm(), PGPUtil.SHA384)
							.setProvider("BC"));

			sGen.init(PGPSignature.BINARY_DOCUMENT, privateKey);

			BCPGOutputStream bcOut = new BCPGOutputStream(bOut);

			sGen.generateOnePassVersion(false).encode(bcOut);

			PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();

			OutputStream lOut = lGen.open(bcOut, PGPLiteralData.BINARY, "_CONSOLE", message.length, new Date());

			for (int i = 0; i != message.length; i++) {
				lOut.write(message[i]);
				sGen.update(message[i]);
			}

			lGen.close();
			sGen.generate().encode(bcOut);
			message = bOut.toByteArray();
		}

		if (doZip) {
			message = zipBytes("tmp.zip", message);
		}

		if (doEncrypt) {
			switch (alg) {
			case _3DES:
				message = encrypt3DES(message, publicKeys);
				break;
			case CAST5:
				message = encryptCAST5(publicKeys, message);
				break;
			default:
				break;
			}
		}

		if (doRadix64) {
			writeDataToArmouredFile(outputFilename, message);
		} else {
			writeDataToHexFile(outputFilename, message);
		}
	}

	/*
	 * public class
	 */
	public static class EncryptedDataWithSecretKey {
		public PGPPublicKeyEncryptedData pbEncryptedData;
		public PGPSecretKey secretKey;

		public EncryptedDataWithSecretKey(PGPPublicKeyEncryptedData pbEncryptedData, PGPSecretKey secretKey) {
			this.pbEncryptedData = pbEncryptedData;
			this.secretKey = secretKey;
		}
	}

	/*------------------------------------------------------------------------------------------------*/
	/*
	 * test methods
	 */
	public static void testEncryptAndDecryptData()
			throws GeneralSecurityException, PGPException, IOException, InvalidExportType {
		java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		java.security.Security.setProperty("crypto.policy", "unlimited");
		KeyManager km = KeyManager.getInstance();

		{
			char[] password = "123".toCharArray();
			String email = "luka2@gmail.com";
			byte[] message = "hello world".getBytes();

			km.generateRSAKeyPairEncryption(password, email, KeySize._2048b, KeySize._4096b);

			KeyRing kr = km.keyRingList.get(0);
			PGPSecretKey sk = kr.getSecretKeyRing().getSecretKey();
			PGPPrivateKey privKey = KeyManager.getPrivateKeyFromSecretKey(sk, password);
			PGPPublicKey encKey = getEncryptinoKey(kr.getPublicKeyRing());

			encryptData(message, privKey, Collections.singletonList(encKey), EncryptionAlg.CAST5, true, true, true,
					true, "testData.pgp");

			kr.exportKeyRing(new File("pub.asc"), KeyRingType.PUBLIC);
			kr.exportKeyRing(new File("sec.asc"), KeyRingType.SECRET);
		}

		{

			byte[] data = decryptData("testData.pgp", "123".toCharArray());
			System.out.println(new String(data));
		}
	}

	public static void main(String[] args) {
		try {
			testEncryptAndDecryptData();
		} catch (GeneralSecurityException | PGPException | IOException | InvalidExportType e) {
			e.printStackTrace();
		}
	}
}
