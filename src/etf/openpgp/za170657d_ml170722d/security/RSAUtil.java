package etf.openpgp.za170657d_ml170722d.security;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.RSAKeyGenParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RSAUtil {

	public static enum SIZE {
		_1024b, _2048b, _4096b
	}

	/**
	 * Set all security providers needed for RSA utility
	 */
	protected static void init() {
		if (Security.getProvider("BC") == null)
			Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Returns a generated set of 1024/2048/4096 bit RSA keys using based parameters
	 * provided.
	 * 
	 * @param bitsize enumeration value of RASUtil.SIZE
	 * @return the generated RSA key pair
	 * @throws GeneralSecurityException if a KeyPairGeneratorSpi implementation for
	 *                                  the specified algorithm is not available
	 *                                  from the specified provider
	 */
	public static KeyPair generateKeyPair(SIZE bitsize) throws GeneralSecurityException {
		init();

		KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA", "BC");

		switch (bitsize) {
		case _1024b:
			keyPair.initialize(1024);
			break;
		case _2048b:
			keyPair.initialize(2048);
			break;
		case _4096b:
			keyPair.initialize(4096);
			break;
		default:
			break;
		}
		return keyPair.generateKeyPair();
	}

	/**
	 * Wrapper method for default values. Returns a generated set of 4096 bit RSA
	 * keys.
	 * 
	 * @return the generated 4096 bit RSA key pair
	 * @throws GeneralSecurityException if a KeyPairGeneratorSpi implementation for
	 *                                  the specified algorithm is not available
	 *                                  from the specified provider
	 */
	public static KeyPair generateKeyPair() throws GeneralSecurityException {
		return generateKeyPair(SIZE._4096b);
	}

	/**
	 * Returns a generated set of 1024/2048/4096 bit RSA keys using based parameters
	 * provided.
	 * 
	 * @param paramSpec RSA parameters to use for key generator
	 * @return the generated key pair
	 * @throws GeneralSecurityException if a KeyPairGeneratorSpi implementation for
	 *                                  the specified algorithm is not available
	 *                                  from the specified provider
	 */
	public static KeyPair generateKeyPair(RSAKeyGenParameterSpec paramSpec) throws GeneralSecurityException {
		init();

		KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA", "BC");

		keyPair.initialize(paramSpec);

		return keyPair.generateKeyPair();
	}

	/**
	 * Returns a generated set of RSA parameters suitable for creating
	 * 1024/2048/4096 bit keys.
	 * 
	 * @param bitsize enumeration value of RASUtil.SIZE
	 * @return the generated RSA key pair
	 * @throws GeneralSecurityException if a KeyPairGeneratorSpi implementation for
	 *                                  the specified algorithm is not available
	 *                                  from the specified provider
	 */
	public static RSAKeyGenParameterSpec generateRSAParams(SIZE bitsize) throws GeneralSecurityException {
		init();

		AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("RSA", "BC");

		switch (bitsize) {
		case _1024b:
			paramGen.init(1024);
			break;
		case _2048b:
			paramGen.init(2048);
			break;
		case _4096b:
			paramGen.init(4096);
			break;
		default:
			break;
		}

		AlgorithmParameters params = paramGen.generateParameters();

		return params.getParameterSpec(RSAKeyGenParameterSpec.class);
	}

	/**
	 * Wrapper method for default values. Returns a generated set of RSA parameters
	 * suitable for creating 4096 bit keys.
	 * 
	 * @return the generated RSA key pair
	 * @throws GeneralSecurityException if a KeyPairGeneratorSpi implementation for
	 *                                  the specified algorithm is not available
	 *                                  from the specified provider
	 */
	public static RSAKeyGenParameterSpec generateRSAParams() throws GeneralSecurityException {
		return generateRSAParams(SIZE._4096b);
	}

	/**
	 * Generate an encoded RSA signature using the passed private key and input
	 * data.
	 * 
	 * @param RSAPrivate private key for generating the signature
	 * @param input      the input to be signed
	 * @return encoded signature
	 * @throws GeneralSecurityException if a KeyPairGeneratorSpi implementation for
	 *                                  the specified algorithm is not available
	 *                                  from the specified provider
	 */
	public static byte[] generateRSASigneture(PrivateKey RSAPrivate, byte[] input) throws GeneralSecurityException {
		init();

		Signature signature = Signature.getInstance("SHA256withRSA", "BC");

		signature.initSign(RSAPrivate);

		signature.update(input);

		return signature.sign();
	}

	/**
	 * Returns true if the passed signature verifies against the passed DSA public
	 * key and input.
	 * 
	 * @param RSAPublic    the public key of the signature creator
	 * @param input        the input that was supposed to have been signed
	 * @param encSignature the encoded signature
	 * @return true if the signature verifies, false otherwise
	 * @throws GeneralSecurityException if a KeyPairGeneratorSpi implementation for
	 *                                  the specified algorithm is not available
	 *                                  from the specified provider
	 */
	public static boolean verifyRSASignature(PublicKey RSAPublic, byte[] input, byte[] encSignature)
			throws GeneralSecurityException {
		init();

		Signature signature = Signature.getInstance("RSA", "BC");

		signature.initVerify(RSAPublic);

		signature.update(input);

		return signature.verify(encSignature);
	}
}
