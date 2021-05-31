package etf.openpgp.za170657d_ml170722d.security;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

public class Encryptor {

	private static String provider = "BC";

	public static enum Type {
		REGULAR, ARMORED
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

	/*----------------------------------------------------------------------------------*/

	/*
	 * public methods
	 */

	public static void enctyptDataCAST5(String filename, List<PGPPublicKey> encryptionKeys, byte[] data, Type type)
			throws IOException {
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
			Type type) throws IOException, PGPException {
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
}
