package etf.openpgp.za170657d_ml170722d.securityV2;

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
import java.util.Arrays;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.util.io.Streams;

import etf.openpgp.za170657d_ml170722d.GUI.EnterPasswordPanel;

public class Decryptor {

	public static void dectyprFile(String inputFilePath, String outputFilePath) throws Exception {

		byte[] read = readEncryptedDataFromFile(inputFilePath);
		InputStream bIn = new ByteArrayInputStream(read);

		bIn = PGPUtil.getDecoderStream(bIn);

		PGPObjectFactory pgpFactory = new PGPObjectFactory(bIn, new JcaKeyFingerprintCalculator());

		Object pgpObj = pgpFactory.nextObject();

		if (pgpObj instanceof PGPOnePassSignatureList || pgpObj instanceof PGPCompressedData
				|| pgpObj instanceof PGPLiteralData) {
			checkForSignatureAndCompression(pgpObj, pgpFactory, outputFilePath);
			bIn.close();
			return;
		}

		PGPEncryptedDataList enc;
		if (pgpObj instanceof PGPEncryptedDataList) {
			enc = (PGPEncryptedDataList) pgpObj;
		} else {
			enc = (PGPEncryptedDataList) pgpFactory.nextObject();
		}

		Iterator<PGPEncryptedData> it = enc.getEncryptedDataObjects();
		PGPPrivateKey privKey = null;
		PGPPublicKeyEncryptedData pubKeyED = null;

		while (privKey == null && it.hasNext()) {
			try {
				pubKeyED = (PGPPublicKeyEncryptedData) it.next();

				PGPSecretKey secretKey = KeyChain.getKeyRing(pubKeyED.getKeyID()).getSecretKey();

				for (int i = 3; i > 0; i--) {
					EnterPasswordPanel panel = new EnterPasswordPanel(i);
					char[] pass = panel.getPassword();

					if (KeyRing.isPasswordForSecretKey(secretKey, pass)) {
						privKey = KeyRing.getPrivateKeyFromSecretKey(secretKey, pass);
						break;
					}
				}

			} catch (PGPException e) {
				e.printStackTrace();
				bIn.close();
				return;
			}
		}

		if (privKey == null) {
			bIn.close();
			throw new Exception("Invalid password. Decryption canceled");
		}

		InputStream clear = pubKeyED.getDataStream(new BcPublicKeyDataDecryptorFactory(privKey));

		PGPObjectFactory plainFact = new PGPObjectFactory(clear, new JcaKeyFingerprintCalculator());
		Object message = plainFact.nextObject();

		checkForSignatureAndCompression(message, plainFact, outputFilePath);

		if (pubKeyED.isIntegrityProtected() && !pubKeyED.verify()) {
			bIn.close();
			throw new Exception("Data is integrity protected but integrity is lost!");
		}

		bIn.close();

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

	private static byte[] readEncryptedDataFromFile(String filename) {
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

	private static void checkForSignatureAndCompression(Object pgpObj, PGPObjectFactory pgpFactory,
			String outputFilePath) throws PGPException, IOException {

		String fileName = "";

		PGPOnePassSignatureList onePassSignatureList = null;
		PGPSignatureList signatureList = null;
		ByteArrayOutputStream actualOutput = new ByteArrayOutputStream();

		while (pgpObj != null) {
			if (pgpObj instanceof PGPCompressedData) {
				PGPCompressedData compressedData = (PGPCompressedData) pgpObj;
				pgpFactory = new PGPObjectFactory(compressedData.getDataStream(), new JcaKeyFingerprintCalculator());
				pgpObj = pgpFactory.nextObject();
			}

			if (pgpObj instanceof PGPLiteralData) {
				PGPLiteralData literalData = (PGPLiteralData) pgpObj;
				fileName = literalData.getFileName();
				Streams.pipeAll(((PGPLiteralData) pgpObj).getInputStream(), actualOutput);
			} else if (pgpObj instanceof PGPOnePassSignatureList) {
				onePassSignatureList = (PGPOnePassSignatureList) pgpObj;
			} else if (pgpObj instanceof PGPSignatureList) {
				signatureList = (PGPSignatureList) pgpObj;
			} else {
				throw new RuntimeException("Unknown message type!");
			}

			try {
				pgpObj = pgpFactory.nextObject();
			} catch (IOException e) {
				break;
			}
		}

		actualOutput.close();

		PGPPublicKey publicKey = null;
		byte[] output = actualOutput.toByteArray();
		if (onePassSignatureList == null || signatureList == null) {

		} else {
			try {
				for (int i = 0; i < onePassSignatureList.size(); i++) {
					PGPOnePassSignature ops = onePassSignatureList.get(i);

					publicKey = KeyChain.getKeyRing(ops.getKeyID()).getPublicKey();

					ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);
					ops.update(output);
					PGPSignature signature = signatureList.get(i);
					if (ops.verify(signature)) {
					} else {
						throw new RuntimeException("Signature verification failed!");
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
				throw new RuntimeException("Can't find public keys");
			}
		}

		OutputStream fOut = new BufferedOutputStream(new FileOutputStream(outputFilePath + fileName));
		fOut.write(output);
		fOut.flush();
		fOut.close();

	}

	public static void main_(String[] args) throws Exception {
		java.security.Security.setProperty("crypto.policy", "unlimited");
		KeyManager.init();
		{
			KeyManager.loadKeyChain();

			String outputFilePath = "data/";
			String inputFilePath = "all_text.txt.gpg";

			Decryptor.dectyprFile(inputFilePath, outputFilePath);

			KeyManager.storeKeyChain();
		}
	}

}
