package etf.openpgp.za170657d_ml170722d.security;

import java.io.IOException;
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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RSAUtil {

	public static enum KeySize {
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
	 * @param bitKeySize enumeration value of RASUtil.KeySize
	 * @return the generated RSA key pair
	 * @throws GeneralSecurityException if a KeyPairGeneratorSpi implementation for
	 *                                  the specified algorithm is not available
	 *                                  from the specified provider
	 */
	public static KeyPair generateRSAKeyPair(KeySize bitKeySize) throws GeneralSecurityException {
		init();

		KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA", "BC");

		switch (bitKeySize) {
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
	public static KeyPair generateRSAKeyPair() throws GeneralSecurityException {
		return generateRSAKeyPair(KeySize._4096b);
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
	public static KeyPair generateRSAKeyPair(RSAKeyGenParameterSpec paramSpec) throws GeneralSecurityException {
		init();

		KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA", "BC");

		keyPair.initialize(paramSpec);

		return keyPair.generateKeyPair();
	}

	/**
	 * Returns a generated set of RSA parameters suitable for creating
	 * 1024/2048/4096 bit keys.
	 * 
	 * @param bitKeySize enumeration value of RASUtil.KeySize
	 * @return the generated RSA key pair
	 * @throws GeneralSecurityException if a KeyPairGeneratorSpi implementation for
	 *                                  the specified algorithm is not available
	 *                                  from the specified provider
	 */
	public static RSAKeyGenParameterSpec generateRSAParams(KeySize bitKeySize) throws GeneralSecurityException {
		init();

		AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("RSA", "BC");

		switch (bitKeySize) {
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
		return generateRSAParams(KeySize._4096b);
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
	public static byte[] generateRSASignature(PrivateKey RSAPrivate, byte[] input) throws GeneralSecurityException {
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

	/**
	 * Fix a faulty DSA signature that has been encoded using unsigned integers.
	 *
	 * @param encSignature the encoded signature.
	 * @return the corrected signature with signed integer components.
	 */
	public static byte[] pathcRSASigature(byte[] encSignature) throws IOException {
		ASN1Sequence seq = ASN1Sequence.getInstance(encSignature);

		ASN1EncodableVector vec = new ASN1EncodableVector();
		vec.add(new ASN1Integer(ASN1Integer.getInstance(seq.getObjectAt(0)).getPositiveValue()));

		vec.add(new ASN1Integer(ASN1Integer.getInstance(seq.getObjectAt(1)).getPositiveValue()));

		return new DERSequence(vec).getEncoded();
	}
}
