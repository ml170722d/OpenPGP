package etf.openpgp.za170657d_ml170722d.securityV2;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

import etf.openpgp.za170657d_ml170722d.security.error.AlreadyInUse;

public class KeyChain {

	/**
	 * 
	 */
	@SuppressWarnings("unused")
	private static final long serialVersionUID = 1L;

	private static List<KeyRing> chain = new ArrayList<KeyRing>();

	public static void add(KeyRing keyRing) throws AlreadyInUse {
		for (KeyRing kr : chain) {
			if (kr.getKeyId() == keyRing.getKeyId()) {
				if (kr.hasPrivateKey() && kr.hasPublicKey())
					throw new AlreadyInUse();

				if (!kr.hasPrivateKey() && keyRing.hasPrivateKey())
					kr.setSecretKeyRing(keyRing.getSecretKeyRing());

				if (!kr.hasPublicKey() && keyRing.hasPublicKey())
					kr.setPublicKeyRing(keyRing.getPublicKeyRing());

				break;
			}
		}
		chain.add(keyRing);
	}

	public static KeyRing getKeyRing(byte[] fingerprint) throws Exception {
		for (KeyRing kr : chain) {
			if (Arrays.equals(kr.getFingerprint(), fingerprint))
				return kr;
		}
		throw new Exception("No key ring with given fingerprint");
	}

	public static KeyRing getKeyRing(long keyId) {
		for (KeyRing kr : chain) {
			if (kr.getKeyId() == keyId)
				return kr;
		}
		return null;
	}

	public static void removeKeyRing(long keyId) {
		for (KeyRing kr : chain) {
			if (kr.getKeyId() == keyId)
				chain.remove(kr);
		}
	}

	public static KeyRing getKeyRing(int index) {
		return chain.get(index);
	}

	public static void removeKeyRing(int index) {
		chain.remove(index);
	}

	public static List<KeyRing> getChain() {
		return chain;
	}

	public static List<PGPSecretKeyRing> getAllSecretKeyRings() {
		return chain.stream().filter(KeyRing::hasPrivateKey).map(KeyRing::getSecretKeyRing)
				.collect(Collectors.toList());
	}

	public static List<PGPSecretKey> getAllSecretKeys() {
		return getAllSecretKeyRings().stream().map(PGPSecretKeyRing::getSecretKey).collect(Collectors.toList());
	}

	public static List<PGPPublicKeyRing> getAllPublicKeyRings() {
		return chain.stream().filter(KeyRing::hasPublicKey).map(KeyRing::getPublicKeyRing).collect(Collectors.toList());
	}

	public static List<PGPPublicKey> getAllPublicKeys() {
		return getAllPublicKeyRings().stream().map(PGPPublicKeyRing::getPublicKey).collect(Collectors.toList());
	}

}
