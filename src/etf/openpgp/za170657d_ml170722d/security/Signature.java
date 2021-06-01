package etf.openpgp.za170657d_ml170722d.security;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;

public class Signature {
	private static byte[] createSignedMessage(int signingAlg, PGPPrivateKey privateKey, byte[] data)
			throws PGPException, IOException {
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		// Create a stream for writing a signature to.
		BCPGOutputStream bcOut = new BCPGOutputStream(bOut);

		// set up the signature generator
		PGPSignatureGenerator sGen = new PGPSignatureGenerator(
				new JcaPGPContentSignerBuilder(signingAlg, PGPUtil.SHA512).setProvider("BC"));

		sGen.init(PGPSignature.BINARY_DOCUMENT, privateKey);

		// Output the signature header
		// the false means we are not generating a nested signature.
		sGen.generateOnePassVersion(false).encode(bcOut);

		// Create the Literal Data record
		PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();

		OutputStream lOut = lGen.open(bcOut, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, data.length, new Date());
		for (int i = 0; i != data.length; i++) {
			lOut.write(data[i]);
			sGen.update(data[i]);
		}

		// Finish Literal Data construction
		lOut.close();

		// Output the actual signature
		sGen.generate().encode(bcOut);

		// close off the stream.
		bcOut.close();

		return bOut.toByteArray();
	}

	public static void createSignedFile(int signingAlg, PGPPrivateKey privateKey, byte[] data)
			throws PGPException, IOException {
		byte[] signedMessage = createSignedMessage(signingAlg, privateKey, data);

		ArmoredOutputStream fileOut = new ArmoredOutputStream(
				new BufferedOutputStream(new FileOutputStream("signedMessage.gpg")));
		fileOut.write(signedMessage);
		fileOut.close();
	}

	public static boolean verifySignedMessage(PGPPublicKey verifyingKey, byte[] pgpSignedData, OutputStream msgStream)
			throws PGPException, IOException {
		// Create a parser for the PGP protocol stream
		JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(pgpSignedData);

		// Read the signature header and set up the verification
		PGPOnePassSignatureList onePassList = (PGPOnePassSignatureList) pgpFact.nextObject();
		PGPOnePassSignature ops = onePassList.get(0);

		ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), verifyingKey);

		// Open up the Literal Data record containing the message
		PGPLiteralData literalData = (PGPLiteralData) pgpFact.nextObject();
		InputStream dIn = literalData.getInputStream();

		// Read the message data
		int ch;
		while ((ch = dIn.read()) >= 0) {
			ops.update((byte) ch);
			msgStream.write(ch);
		}

		dIn.close();

		// Read and verify the signature
		PGPSignatureList sigList = (PGPSignatureList) pgpFact.nextObject();
		PGPSignature sig = sigList.get(0);

		return ops.verify(sig);
	}
}
