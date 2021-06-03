package etf.openpgp.za170657d_ml170722d.security;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class Decryptor3 {

//	public static MainView mainView;

	public static void decryptFile(String inputFilePath, String outputFilePath)
			throws IOException, NoSuchProviderException, SignatureException, PGPException {

		Security.addProvider(new BouncyCastleProvider());
		InputStream in = new BufferedInputStream(new FileInputStream(inputFilePath));
		prepareForDecryption(in, outputFilePath);

	}

	public static void prepareForDecryption(InputStream outFileIn, String outFilePath)
			throws IOException, SignatureException, PGPException {

		ByteBuffer buf = ByteBuffer.allocate(1024 * 10);
		byte[] read = new byte[1024];

		while (outFileIn.read(read, 0, 1024) != -1) {
			buf.put(read);
		}

		BASE64Encoder en = new BASE64Encoder();
		String temp = en.encode(buf.array());

		byte[] newB = null;
		BASE64Decoder en1 = new BASE64Decoder();

		newB = en1.decodeBuffer(temp);

		ByteArrayInputStream bais = new ByteArrayInputStream(newB);

		decryptAndVerify(bais, outFilePath);

	}

	public static void decryptAndVerify(InputStream in, String outFilePath)
			throws IOException, SignatureException, PGPException {

		String fileName = "";

		in = PGPUtil.getDecoderStream(in);

		PGPObjectFactory pgpF = new PGPObjectFactory(in, new JcaKeyFingerprintCalculator());
		PGPEncryptedDataList enc;

		Object pgpObj = pgpF.nextObject();

		if (pgpObj instanceof PGPOnePassSignatureList || pgpObj instanceof PGPCompressedData
				|| pgpObj instanceof PGPLiteralData) {
			checkForSignatureAndCompression(pgpObj, pgpF, outFilePath);
			return;
		}

		if (pgpObj instanceof PGPEncryptedDataList) {
			enc = (PGPEncryptedDataList) pgpObj;
		} else {
			enc = (PGPEncryptedDataList) pgpF.nextObject();
		}

		JPanel panel = new JPanel();
		JLabel label = new JLabel("Enter a password:");
		JPasswordField pass = new JPasswordField(10);
		panel.add(label);
		panel.add(pass);
		String[] options = new String[] { "OK", "Cancel" };
		int option = JOptionPane.showOptionDialog(null, panel, "Secret key requires password", JOptionPane.NO_OPTION,
				JOptionPane.WARNING_MESSAGE, null, options, options[1]);
		if (option == 0) {

			char[] passwd = pass.getPassword();
			Iterator it = enc.getEncryptedDataObjects();
			PGPPrivateKey sKey = null;
			PGPPublicKeyEncryptedData pbe = null;
			while (sKey == null && it.hasNext()) {
				try {
					pbe = (PGPPublicKeyEncryptedData) it.next();
					sKey = KeyManager.findPrivateKey(pbe.getKeyID(), passwd);

				} catch (NoSuchProviderException ex) {

				}
			}
			if (sKey == null) {
				JOptionPane.showMessageDialog(mainView, "Secret key for message not found!", "Error",
						JOptionPane.ERROR_MESSAGE);
				return;

			}

			InputStream clear = pbe.getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));

			PGPObjectFactory plainFact = new PGPObjectFactory(clear, new JcaKeyFingerprintCalculator());
			Object message;

			message = plainFact.nextObject();

			checkForSignatureAndCompression(message, plainFact, outFilePath);

			if (pbe.isIntegrityProtected() && !pbe.verify()) {
				JOptionPane.showMessageDialog(mainView, "Data is integrity protected but integrity is lost!", "Error",
						JOptionPane.ERROR_MESSAGE);

			}

		}
	}

	private static void checkForSignatureAndCompression(Object pgpObj, PGPObjectFactory pgpF, String outFilePath)
			throws PGPException, SignatureException, IOException {

		String fileName = "";

		PGPOnePassSignatureList onePassSignatureList = null;
		PGPSignatureList signatureList = null;
		PGPCompressedData compressedData;
		PGPLiteralData literalData = null;
		ByteArrayOutputStream actualOutput = new ByteArrayOutputStream();

		while (pgpObj != null) {

			if (pgpObj instanceof PGPCompressedData) {
				compressedData = (PGPCompressedData) pgpObj;
				pgpF = new PGPObjectFactory(compressedData.getDataStream(), new JcaKeyFingerprintCalculator());
				pgpObj = pgpF.nextObject();
			}

			if (pgpObj instanceof PGPLiteralData) {

				literalData = (PGPLiteralData) pgpObj;
				fileName = ((PGPLiteralData) pgpObj).getFileName();
				Streams.pipeAll(((PGPLiteralData) pgpObj).getInputStream(), actualOutput);

			} else if (pgpObj instanceof PGPOnePassSignatureList) {
				onePassSignatureList = (PGPOnePassSignatureList) pgpObj;
			} else if (pgpObj instanceof PGPSignatureList) {
				signatureList = (PGPSignatureList) pgpObj;

			} else {
				JOptionPane.showMessageDialog(mainView, "Unknown message type!", "Error", JOptionPane.ERROR_MESSAGE);
				return;

			}

			try {
				pgpObj = pgpF.nextObject();
			} catch (IOException ex) {
				break;
			}
		}

		actualOutput.close();
		PGPPublicKey publicKey = null;
		byte[] output = actualOutput.toByteArray();
		if (onePassSignatureList == null || signatureList == null) {

		} else {

			for (int i = 0; i < onePassSignatureList.size(); i++) {
				PGPOnePassSignature ops = onePassSignatureList.get(0);

				publicKey = KeyManager.publicKeyRingCollection.getPublicKey(ops.getKeyID());
				if (publicKey != null) {
					ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);
					ops.update(output);
					PGPSignature signature = signatureList.get(i);
					if (ops.verify(signature)) {
						Iterator<?> userIds = publicKey.getUserIDs();
						while (userIds.hasNext()) {
							String userId = (String) userIds.next();

							JOptionPane.showMessageDialog(mainView, String.format("Signed by : {%s}", userId),
									"Signature verified", JOptionPane.INFORMATION_MESSAGE);
						}

					} else {
						JOptionPane.showMessageDialog(mainView, "Signature verification failed!", "Error",
								JOptionPane.ERROR_MESSAGE);
						return;

					}
				}
			}

		}

		OutputStream fOut = new BufferedOutputStream(new FileOutputStream(outFilePath + "//" + fileName));
		fOut.write(output);
		fOut.flush();
		fOut.close();
		JOptionPane.showMessageDialog(mainView, "Finished!", "Success", JOptionPane.INFORMATION_MESSAGE);
	}
	// }
}