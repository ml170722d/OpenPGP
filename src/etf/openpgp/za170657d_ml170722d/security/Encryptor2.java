package etf.openpgp.za170657d_ml170722d.security;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import etf.openpgp.za170657d_ml170722d.security.KeyManager.KeyType;
import etf.openpgp.za170657d_ml170722d.security.RSAUtil.KeySize;

public class Encryptor2 {

//	private static int BUFFER_SIZE = 1 << 12;
//	private static BouncyCastleProvider bcProvider = new BouncyCastleProvider();

	public static enum SymmetricAlgorithmTags {
		CAST5, _3DES
	}

	public static void encryptFile(String outputFilePath, String inputFilePath, String inputFileName,
			String publicKeyFileName, String privateKeyFileName, boolean withIntegrityCheck, boolean withRadix64,
			int symetricAlgorithm, boolean withZip, boolean withEncryption, boolean withSignature)
			throws IOException, NoSuchProviderException, PGPException, Exception {

		Security.addProvider(new BouncyCastleProvider());

		PGPPublicKey pubKey = null;
		PGPSecretKey secKey = null;

		if (withEncryption) {
			pubKey = KeyManager.importPublicKeyRingFromFile(publicKeyFileName);
		}

		if (withSignature) {
			secKey = KeyManager.readSecretKeyFromFile(privateKeyFileName);
		}

	}

	/*
	 * public static void encryptData(String readFrom, String saveAs, int sender,
	 * int[] receiver, boolean encrypt, SymmetricAlgorithmTags algorithm, boolean
	 * radix64, boolean sign, char[] password, boolean zip, boolean integrityCheck)
	 * throws IOException, PGPException {
	 * 
	 * Provider provider = new BouncyCastleProvider();
	 * 
	 * OutputStream dataOutputStream = getTargetOutputStream(radix64, saveAs);
	 * 
	 * List<KeyRing> list = KeyManager.getInstance().keyRingList; List<PGPPublicKey>
	 * pubKeyList = new ArrayList<>(); for (int i = 0; i < receiver.length; i++) {
	 * pubKeyList.add(getPublicKey(list.get(receiver[i]))); }
	 * 
	 * if (encrypt) { switch (algorithm) { case _3DES: dataOutputStream =
	 * createEncryptedData(pubKeyList, SymmetricKeyAlgorithmTags.TRIPLE_DES,
	 * integrityCheck, provider, dataOutputStream); break; case CAST5:
	 * dataOutputStream = createEncryptedData(pubKeyList,
	 * SymmetricKeyAlgorithmTags.CAST5, integrityCheck, provider, dataOutputStream);
	 * break; default: throw new
	 * RuntimeException("Bad symmetric algorithm tag given"); } }
	 * 
	 * if (zip) { dataOutputStream = zip(dataOutputStream); }
	 * 
	 * PGPSignatureGenerator sGen = null; if (sign) { PGPSecretKey sk =
	 * list.get(sender).getSecretKeyRing().getSecretKey(); sGen = sign(sk, password,
	 * dataOutputStream, provider); }
	 * 
	 * dataOutputStream = createLiteralData(dataOutputStream);
	 * 
	 * byte[] buff = new byte[BUFFER_SIZE]; int len; InputStream source = new
	 * FileInputStream(readFrom);
	 * 
	 * while ((len = source.read(buff, 0, buff.length)) > 0) {
	 * dataOutputStream.write(buff, 0, len); if (sGen != null) sGen.update(buff, 0,
	 * len); }
	 * 
	 * source.close(); }
	 * 
	 * private static PGPPublicKey getPublicKey(KeyRing keyRing) {
	 * Iterator<PGPPublicKey> itPK = keyRing.getPublicKeyRing().getPublicKeys();
	 * 
	 * while (itPK.hasNext()) { PGPPublicKey pk = itPK.next(); if
	 * (pk.isEncryptionKey()) return pk; } return null; }
	 * 
	 * private static OutputStream getTargetOutputStream(boolean radix64, String
	 * filename) throws FileNotFoundException { if (radix64) return new
	 * BufferedOutputStream(new FileOutputStream(filename)); else return new
	 * ArmoredOutputStream(new BufferedOutputStream(new
	 * FileOutputStream(filename))); }
	 * 
	 * private static OutputStream createEncryptedData(List<PGPPublicKey>
	 * publicKeys, int algorythm, boolean integrityCheck, Provider provider,
	 * OutputStream data) throws IOException, PGPException {
	 * 
	 * PGPEncryptedDataGenerator gen = new PGPEncryptedDataGenerator(new
	 * JcePGPDataEncryptorBuilder(algorythm)
	 * .setWithIntegrityPacket(integrityCheck).setSecureRandom(new
	 * SecureRandom()).setProvider(provider));
	 * 
	 * if (publicKeys.isEmpty()) throw new
	 * RuntimeException("Cannot pass 0 encryption keys.");
	 * 
	 * for (PGPPublicKey publicKey : publicKeys) { gen.addMethod(new
	 * JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider(provider)); }
	 * 
	 * return gen.open(data, new byte[BUFFER_SIZE]); }
	 * 
	 * private static OutputStream zip(OutputStream data) throws IOException {
	 * PGPCompressedDataGenerator compressedDataGenerator = new
	 * PGPCompressedDataGenerator( CompressionAlgorithmTags.ZIP);
	 * 
	 * return compressedDataGenerator.open(data); }
	 * 
	 * private static PGPSignatureGenerator sign(PGPSecretKey secretKey, char[]
	 * password, OutputStream data, Provider provider) throws PGPException,
	 * IOException { PGPPrivateKey privateKey =
	 * KeyManager.getPrivateKeyFromSecretKey(secretKey, password);
	 * 
	 * PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator( new
	 * JcaPGPContentSignerBuilder(privateKey.getPublicKeyPacket().getAlgorithm(),
	 * PGPUtil.SHA384) .setProvider(provider));
	 * 
	 * signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
	 * 
	 * String userId = secretKey.getPublicKey().getUserIDs().next();
	 * PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
	 * spGen.setSignerUserID(false, userId.getBytes());
	 * signatureGenerator.setHashedSubpackets(spGen.generate());
	 * 
	 * signatureGenerator.generateOnePassVersion(false).encode(data);
	 * 
	 * return signatureGenerator; }
	 * 
	 * private static OutputStream createLiteralData(OutputStream data) throws
	 * IOException { PGPLiteralDataGenerator dataGenerator = new
	 * PGPLiteralDataGenerator(); return dataGenerator.open(data,
	 * PGPLiteralData.BINARY, "tmpdata", new Date(), new byte[BUFFER_SIZE]); }
	 * 
	 * public static void main(String[] args) throws IOException, PGPException,
	 * GeneralSecurityException { java.security.Security.addProvider(new
	 * org.bouncycastle.jce.provider.BouncyCastleProvider());
	 * java.security.Security.setProperty("crypto.policy", "unlimited");
	 * 
	 * { char[] password = "a".toCharArray();
	 * 
	 * KeyManager km = KeyManager.getInstance();
	 * 
	 * // km.loadKeyRings(); km.generateRSAKeyPairEncryption(password, "aki <aki>",
	 * KeySize._1024b, KeySize._1024b); km.generateRSAKeyPairEncryption(password,
	 * "luka <luka>", KeySize._1024b, KeySize._1024b);
	 * 
	 * int sender = 0; int receiver[] = { 1 };
	 * 
	 * km.exportKey(sender, new File("pub_" + sender + ".asc"), KeyType.PUBLIC);
	 * km.exportKey(sender, new File("priv_" + sender + ".asc"), KeyType.PRIVATE);
	 * 
	 * for (int i = 0; i < receiver.length; i++) { km.exportKey(receiver[i], new
	 * File("pub_" + receiver[i] + ".asc"), KeyType.PUBLIC);
	 * km.exportKey(receiver[i], new File("priv_" + receiver[i] + ".asc"),
	 * KeyType.PRIVATE); }
	 * 
	 * Encryptor2.encryptData("text.txt", "textDecr.txt.pgp", sender, receiver,
	 * false, SymmetricAlgorithmTags.CAST5, false, false, password, false, false); }
	 * }
	 */
}
