package etf.openpgp.za170657d_ml170722d.securityV2;

import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;

import etf.openpgp.za170657d_ml170722d.GUI.EnterPasswordPanel;
import etf.openpgp.za170657d_ml170722d.security.error.AlreadyInUse;
import etf.openpgp.za170657d_ml170722d.security.error.InvalidType;
import etf.openpgp.za170657d_ml170722d.securityV2.KeyRing.KeyRingTags;
import etf.openpgp.za170657d_ml170722d.securityV2.RSAUtil.KeySizeTags;

public class Encryptor {

	private static int BUFFER_SIZE = 1 << 12;

	public static void enctyptFile(String outputFilePath, String inputFilePath, PGPPublicKey publicKey,
			PGPSecretKey secretKey, boolean integrityCheck, boolean radix64, boolean encrypt, int symmetricAlgorithm,
			boolean zip, boolean sign) throws Exception {

		String embededFileName = "embeded";

		InputStream in = new FileInputStream(inputFilePath);
		OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFilePath));

		if (radix64)
			out = new ArmoredOutputStream(out);

		PGPPrivateKey privateKey = null;

		if (sign) {
			for (int i = 3; i > 0; i--) {
				try {
					EnterPasswordPanel panel = new EnterPasswordPanel(i);
					char[] pass = panel.getPassword();
					if (KeyRing.isPasswordForSecretKey(secretKey, pass)) {
						privateKey = KeyRing.getPrivateKeyFromSecretKey(secretKey, pass);
						break;
					}
				} catch (PGPException e) {
				}
			}

			if (privateKey == null) {
				in.close();
				out.close();
				throw new Exception("Invalid password. Cand't get private key");
			}

			SecureRandom rand = new SecureRandom();

			OutputStream cOut;
			PGPEncryptedDataGenerator encryptedDataGenerator = null;

			if (encrypt) {
				encryptedDataGenerator = new PGPEncryptedDataGenerator(new BcPGPDataEncryptorBuilder(symmetricAlgorithm)
						.setWithIntegrityPacket(integrityCheck).setSecureRandom(rand));
				encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(publicKey));

				if (zip) {
					cOut = new PGPCompressedDataGenerator(PGPCompressedData.ZIP)
							.open(encryptedDataGenerator.open(out, new byte[BUFFER_SIZE]), new byte[BUFFER_SIZE]);
				} else {
					cOut = encryptedDataGenerator.open(out, new byte[BUFFER_SIZE]);
				}
			} else {
				if (zip) {
					cOut = new PGPCompressedDataGenerator(PGPCompressedData.ZIP).open(out, new byte[BUFFER_SIZE]);
				} else {
					cOut = out;
				}
			}

			PGPSignatureGenerator signatureGenerator = null;

			if (sign) {
				signatureGenerator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(
						privateKey.getPublicKeyPacket().getAlgorithm(), HashAlgorithmTags.SHA1));
				signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
				signatureGenerator.generateOnePassVersion(true).encode(cOut);
			}

			OutputStream finalOut = new PGPLiteralDataGenerator().open(cOut, PGPLiteralData.BINARY, embededFileName,
					new Date(), new byte[BUFFER_SIZE]);

			byte[] buff = new byte[BUFFER_SIZE];
			int len;
			while ((len = in.read(buff)) > 0) {
				finalOut.write(buff, 0, len);
				if (sign) {
					signatureGenerator.update(buff, 0, len);
				}
			}

			finalOut.close();
			in.close();
			if (sign)
				signatureGenerator.generate().encode(cOut);

			cOut.close();
			if (encrypt)
				encryptedDataGenerator.close();

			out.close();
		}
	}

	public static void enctyptFile(String outputFilePath, String inputFilePath, List<PGPPublicKey> publicKeys,
			PGPSecretKey secretKey, boolean integrityCheck, boolean radix64, boolean encrypt, int symmetricAlgorithm,
			boolean zip, boolean sign) throws Exception {

		String embededFileName = "embeded";

		InputStream in = new FileInputStream(inputFilePath);
		OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFilePath));

		if (radix64)
			out = new ArmoredOutputStream(out);

		PGPPrivateKey privateKey = null;

		if (sign) {
			for (int i = 3; i > 0; i--) {
				try {
					EnterPasswordPanel panel = new EnterPasswordPanel(i);
					char[] pass = panel.getPassword();
					if (KeyRing.isPasswordForSecretKey(secretKey, pass)) {
						privateKey = KeyRing.getPrivateKeyFromSecretKey(secretKey, pass);
						break;
					}
				} catch (PGPException e) {
				}
			}

			if (privateKey == null) {
				in.close();
				out.close();
				throw new Exception("Invalid password. Cand't get private key");
			}

			SecureRandom rand = new SecureRandom();

			OutputStream cOut;
			PGPEncryptedDataGenerator encryptedDataGenerator = null;

			if (encrypt) {
				encryptedDataGenerator = new PGPEncryptedDataGenerator(new BcPGPDataEncryptorBuilder(symmetricAlgorithm)
						.setWithIntegrityPacket(integrityCheck).setSecureRandom(rand));

				for (PGPPublicKey publicKey : publicKeys)
					encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(publicKey));

				if (zip) {
					cOut = new PGPCompressedDataGenerator(PGPCompressedData.ZIP)
							.open(encryptedDataGenerator.open(out, new byte[BUFFER_SIZE]), new byte[BUFFER_SIZE]);
				} else {
					cOut = encryptedDataGenerator.open(out, new byte[BUFFER_SIZE]);
				}
			} else {
				if (zip) {
					cOut = new PGPCompressedDataGenerator(PGPCompressedData.ZIP).open(out, new byte[BUFFER_SIZE]);
				} else {
					cOut = out;
				}
			}

			PGPSignatureGenerator signatureGenerator = null;

			if (sign) {
				signatureGenerator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(
						privateKey.getPublicKeyPacket().getAlgorithm(), HashAlgorithmTags.SHA1));
				signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
				signatureGenerator.generateOnePassVersion(true).encode(cOut);
			}

			OutputStream finalOut = new PGPLiteralDataGenerator().open(cOut, PGPLiteralData.BINARY, embededFileName,
					new Date(), new byte[BUFFER_SIZE]);

			byte[] buff = new byte[BUFFER_SIZE];
			int len;
			while ((len = in.read(buff)) > 0) {
				finalOut.write(buff, 0, len);
				if (sign) {
					signatureGenerator.update(buff, 0, len);
				}
			}

			finalOut.close();
			in.close();
			if (sign)
				signatureGenerator.generate().encode(cOut);

			cOut.close();
			if (encrypt)
				encryptedDataGenerator.close();

			out.close();
		}
	}

	public static void main(String[] args)
			throws NoSuchAlgorithmException, PGPException, AlreadyInUse, InvalidType, IOException {

		java.security.Security.setProperty("crypto.policy", "unlimited");
		KeyManager.init();

		char[] password = "a".toCharArray();
		String userId[] = { "luka <luka>", "aki <aki>", "a <a>", "b <b>" };

		int index = 0;
		for (int i = 0; i < userId.length; i++) {
			KeyManager.generateRSAKeyPair(password, userId[i], KeySizeTags._1024b);
			KeyManager.exportKey(index, KeyRingTags.PUBLIC, "pub_" + index);
			KeyManager.exportKey(index, KeyRingTags.PRIVATE, "priv_" + index);
			index++;
		}

		{
			String outputFileName = "all_text.txt.gpg";
			String inputFilePath = "text.txt";
//			String inputFileName = "tmp";

			// receivers
			List<PGPPublicKey> list = new ArrayList<PGPPublicKey>();
			for (int i = 1; i < KeyChain.getChain().size(); i++) {
				PGPPublicKey publicKey = KeyChain.getKeyRing(i).getPublicKey();
				list.add(publicKey);
			}
			// sender
			PGPSecretKey secretKey = KeyChain.getKeyRing(0).getSecretKey();

			try {
				Encryptor.enctyptFile(outputFileName, inputFilePath, list, secretKey, true, true, true,
						SymmetricKeyAlgorithmTags.CAST5, true, true);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
		//fails
		{
			String outputFileName = "notSigned_text.txt.gpg";
			String inputFilePath = "text.txt";
//			String inputFileName = "tmp";

			// receivers
			List<PGPPublicKey> list = new ArrayList<PGPPublicKey>();
			for (int i = 1; i < KeyChain.getChain().size(); i++) {
				PGPPublicKey publicKey = KeyChain.getKeyRing(i).getPublicKey();
				list.add(publicKey);
			}
			// sender
			PGPSecretKey secretKey = KeyChain.getKeyRing(0).getSecretKey();

			try {
				Encryptor.enctyptFile(outputFileName, inputFilePath, list, secretKey, true, true, true,
						SymmetricKeyAlgorithmTags.CAST5, true, true);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
		{
			String outputFileName = "notZiped_text.txt.gpg";
			String inputFilePath = "text.txt";
//			String inputFileName = "tmp";

			// receivers
			List<PGPPublicKey> list = new ArrayList<PGPPublicKey>();
			for (int i = 1; i < KeyChain.getChain().size(); i++) {
				PGPPublicKey publicKey = KeyChain.getKeyRing(i).getPublicKey();
				list.add(publicKey);
			}
			// sender
			PGPSecretKey secretKey = KeyChain.getKeyRing(0).getSecretKey();

			try {
				Encryptor.enctyptFile(outputFileName, inputFilePath, list, secretKey, true, true, true,
						SymmetricKeyAlgorithmTags.CAST5, false, true);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
		//fails
		{
			String outputFileName = "notSignedZiped_text.txt.gpg";
			String inputFilePath = "text.txt";
//			String inputFileName = "tmp";

			// receivers
			List<PGPPublicKey> list = new ArrayList<PGPPublicKey>();
			for (int i = 1; i < KeyChain.getChain().size(); i++) {
				PGPPublicKey publicKey = KeyChain.getKeyRing(i).getPublicKey();
				list.add(publicKey);
			}
			// sender
			PGPSecretKey secretKey = KeyChain.getKeyRing(0).getSecretKey();

			try {
				Encryptor.enctyptFile(outputFileName, inputFilePath, list, secretKey, true, true, true,
						SymmetricKeyAlgorithmTags.CAST5, false, true);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
		{
			String outputFileName = "notChecked_text.txt.gpg";
			String inputFilePath = "text.txt";
//			String inputFileName = "tmp";

			// receivers
			List<PGPPublicKey> list = new ArrayList<PGPPublicKey>();
			for (int i = 1; i < KeyChain.getChain().size(); i++) {
				PGPPublicKey publicKey = KeyChain.getKeyRing(i).getPublicKey();
				list.add(publicKey);
			}
			// sender
			PGPSecretKey secretKey = KeyChain.getKeyRing(0).getSecretKey();

			try {
				Encryptor.enctyptFile(outputFileName, inputFilePath, list, secretKey, false, true, true,
						SymmetricKeyAlgorithmTags.CAST5, true, true);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
		{
			String outputFileName = "notEncrypted_text.txt.gpg";
			String inputFilePath = "text.txt";
//			String inputFileName = "tmp";

			// receivers
			List<PGPPublicKey> list = new ArrayList<PGPPublicKey>();
			for (int i = 1; i < KeyChain.getChain().size(); i++) {
				PGPPublicKey publicKey = KeyChain.getKeyRing(i).getPublicKey();
				list.add(publicKey);
			}
			// sender
			PGPSecretKey secretKey = KeyChain.getKeyRing(0).getSecretKey();

			try {
				Encryptor.enctyptFile(outputFileName, inputFilePath, list, secretKey, true, true, false,
						SymmetricKeyAlgorithmTags.CAST5, true, true);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
		{
			String outputFileName = "notRadix64_text.txt.gpg";
			String inputFilePath = "text.txt";
//			String inputFileName = "tmp";

			// receivers
			List<PGPPublicKey> list = new ArrayList<PGPPublicKey>();
			for (int i = 1; i < KeyChain.getChain().size(); i++) {
				PGPPublicKey publicKey = KeyChain.getKeyRing(i).getPublicKey();
				list.add(publicKey);
			}
			// sender
			PGPSecretKey secretKey = KeyChain.getKeyRing(0).getSecretKey();

			try {
				Encryptor.enctyptFile(outputFileName, inputFilePath, list, secretKey, true, false, true,
						SymmetricKeyAlgorithmTags.CAST5, true, true);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
		//fails
		{
			String outputFileName = "notAll_text.txt.gpg";
			String inputFilePath = "text.txt";
//			String inputFileName = "tmp";

			// receivers
			List<PGPPublicKey> list = new ArrayList<PGPPublicKey>();
			for (int i = 1; i < KeyChain.getChain().size(); i++) {
				PGPPublicKey publicKey = KeyChain.getKeyRing(i).getPublicKey();
				list.add(publicKey);
			}
			// sender
			PGPSecretKey secretKey = KeyChain.getKeyRing(0).getSecretKey();

			try {
				Encryptor.enctyptFile(outputFileName, inputFilePath, list, secretKey, false, false, false,
						SymmetricKeyAlgorithmTags.CAST5, false, true);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

}
