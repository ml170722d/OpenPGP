package etf.openpgp.za170657d_ml170722d.security;

import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
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
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

public class Encryptor3 {

	public static void encryptFile(String outputFilePath, String inputFilePath, String inputFileName,
			PGPPublicKey publicKeyFileName, PGPSecretKey privateKeyFileName, boolean withIntegrityCheck, boolean withRadix64,
			int symetricAlgorithm, boolean withZip, boolean withEncryption, boolean withSignature)
			throws IOException, NoSuchProviderException, PGPException, Exception {

		Security.addProvider(new BouncyCastleProvider());

//		PGPPublicKey pubKey = null;
//		PGPSecretKey secKey = null;
//
//		if (withEncryption) {
//			pubKey = KeyManager3.readPublicKeyFromFile(publicKeyFileName);
//		}
//
//		if (withSignature) {
//			secKey = KeyManager3.readSecretKeyFromFile(privateKeyFileName);
//		}

		signEncryptMessage(outputFilePath, inputFilePath, inputFileName, publicKeyFileName, privateKeyFileName, symetricAlgorithm, withRadix64,
				withEncryption, withIntegrityCheck, withZip, withSignature);

	}

	public static void signEncryptMessage(String outputFilePath, String inputFilePath, String inputFileName,
			PGPPublicKey publicKey, PGPSecretKey secretKey, int symetricAlgorithm, boolean withRadix64,
			boolean withEncryption, boolean withIntegrityCheck, boolean withZip, boolean withSignature)
			throws Exception {

		InputStream in = new FileInputStream(inputFilePath);
		OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFilePath));

		if (withRadix64) {
			out = new ArmoredOutputStream(out);
		}

		PGPPrivateKey privateKey = null;

		if (withSignature) {
			JPanel panel = new JPanel();
			JLabel label = new JLabel("Enter a password:");
			JPasswordField pass = new JPasswordField(10);
			panel.add(label);
			panel.add(pass);
			String[] options = new String[] { "OK", "Cancel" };
			int option = JOptionPane.showOptionDialog(null, panel, "Secret key requires password",
					JOptionPane.NO_OPTION, JOptionPane.WARNING_MESSAGE, null, options, options[1]);
			if (option == 0) {
				char[] password = pass.getPassword();
				privateKey = secretKey
						.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(password));
			}

		}

		SecureRandom rand = new SecureRandom();

		OutputStream cOut;
		PGPEncryptedDataGenerator encryptedDataGenerator = null;

		if (withEncryption) {

			encryptedDataGenerator = new PGPEncryptedDataGenerator(new BcPGPDataEncryptorBuilder(symetricAlgorithm)
					.setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(rand));
			encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(publicKey));

			if (withZip) {
				cOut = new PGPCompressedDataGenerator(PGPCompressedData.ZIP)
						.open(encryptedDataGenerator.open(out, new byte[4096]), new byte[4096]);
			} else {
				cOut = encryptedDataGenerator.open(out, new byte[4096]);
			}

		} else {
			if (withZip) {
				cOut = new PGPCompressedDataGenerator(PGPCompressedData.ZIP).open(out, new byte[4096]);

			} else {
				cOut = out;
			}

		}

		PGPSignatureGenerator signatureGenerator = null;

		if (withSignature) {

			signatureGenerator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(
					privateKey.getPublicKeyPacket().getAlgorithm(), HashAlgorithmTags.SHA1));
			signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
			signatureGenerator.generateOnePassVersion(true).encode(cOut);
		}

		OutputStream finalOut = new PGPLiteralDataGenerator().open(cOut, PGPLiteralData.BINARY, inputFileName,
				new Date(), new byte[4096]);

		byte[] buf = new byte[4096];
		int len;
		while ((len = in.read(buf)) > 0) {
			finalOut.write(buf, 0, len);
			if (withSignature) {
				signatureGenerator.update(buf, 0, len);
			}
		}

		finalOut.close();
		in.close();
		if (withSignature) {
			signatureGenerator.generate().encode(cOut);
		}
		cOut.close();
		if (withEncryption) {
			encryptedDataGenerator.close();
		}

		out.close();

	}

}