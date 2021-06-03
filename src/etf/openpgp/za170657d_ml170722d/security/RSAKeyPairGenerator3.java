package etf.openpgp.za170657d_ml170722d.security;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

public class RSAKeyPairGenerator3 {
	public static PGPSecretKey generateKeyPair(KeyPair pair, String identity, char[] passPhrase) {
		try {

			PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build()
					.get(HashAlgorithmTags.SHA1);
			PGPKeyPair keyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, pair, new Date());
			PGPSecretKey secretKey = new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION, keyPair, identity, sha1Calc,
					null, null,
					new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
					new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC")
							.build(passPhrase));
			PGPPublicKey key = secretKey.getPublicKey();

			return secretKey;

		} catch (PGPException ex) {
			Logger.getLogger(RSAKeyPairGenerator3.class.getName()).log(Level.SEVERE, null, ex);
		}

		return null;
	}

	public static void exportKeyPair(PGPSecretKey secretKey, boolean armor)
			throws IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException {

		PGPPublicKey key = secretKey.getPublicKey();

		OutputStream secretOut = new FileOutputStream(
				"secretkeys/" + Long.toHexString(key.getKeyID()).toUpperCase() + ".asc");
		OutputStream publicOut = new FileOutputStream(
				"publickeys/" + Long.toHexString(key.getKeyID()).toUpperCase() + ".asc");

		if (armor) {
			secretOut = new ArmoredOutputStream(secretOut);
		}

		secretKey.encode(secretOut);

		secretOut.close();

		if (armor) {
			publicOut = new ArmoredOutputStream(publicOut);
		}

		key.encode(publicOut);

		publicOut.close();

		KeyManager3.initPublicKeysRing();
	}

	public static void generateAndExportKeyPair(String identity, char[] passphrase, int keyLength) throws Exception {

		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
		kpg.initialize(keyLength);

		KeyPair kp = kpg.generateKeyPair();

		PGPSecretKey secretKey = generateKeyPair(kp, identity, passphrase);
		exportKeyPair(secretKey, true);

	}
}
