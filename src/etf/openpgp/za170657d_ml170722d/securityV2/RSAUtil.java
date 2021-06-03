package etf.openpgp.za170657d_ml170722d.securityV2;

import java.io.IOException;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAKeyGenParameterSpec;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

import etf.openpgp.za170657d_ml170722d.security.RSAUtil.KeySize;

public class RSAUtil {

	public static interface KeySizeTags {
		public static int _1024b = 1024;
		public static int _2048b = 2048;
		public static int _4096b = 4096;
	}

	public static KeyPair generateRSAKeyPari(int size, Provider provider) throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", provider);
		keyPairGenerator.initialize(size);

		return keyPairGenerator.generateKeyPair();
	}

	public static KeyPair generateRSAKeyPair(RSAKeyGenParameterSpec paramSpec, Provider provider)
			throws GeneralSecurityException {
		KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA", provider);
		keyPair.initialize(paramSpec);

		return keyPair.generateKeyPair();
	}

	public static RSAKeyGenParameterSpec generateRSAParams(KeySize bitKeySize, Provider provider)
			throws GeneralSecurityException {
		AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("RSA", provider);
		AlgorithmParameters params = paramGen.generateParameters();

		return params.getParameterSpec(RSAKeyGenParameterSpec.class);
	}

	public static boolean verifyRSASignature(PublicKey RSAPublic, byte[] input, byte[] encSignature, Provider provider)
			throws GeneralSecurityException {
		Signature signature = Signature.getInstance("RSA", provider);
		signature.initVerify(RSAPublic);
		signature.update(input);

		return signature.verify(encSignature);
	}

	public static byte[] patchRSASigature(byte[] encSignature) throws IOException {
		ASN1Sequence seq = ASN1Sequence.getInstance(encSignature);
		ASN1EncodableVector vec = new ASN1EncodableVector();
		vec.add(new ASN1Integer(ASN1Integer.getInstance(seq.getObjectAt(0)).getPositiveValue()));
		vec.add(new ASN1Integer(ASN1Integer.getInstance(seq.getObjectAt(1)).getPositiveValue()));

		return new DERSequence(vec).getEncoded();
	}
}
