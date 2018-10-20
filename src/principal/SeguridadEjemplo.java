/**
 * Ejemplo de cifrados y seguridad!
 */
package principal;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import java.awt.Desktop;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.*;





public class SeguridadEjemplo {
	public static final String HMACMD5 = "HMACMD5";
	public static final String HMACSHA1 = "HMACSHA1";
	public static final String HMACSHA256 = "HMACSHA256";
	private final static String ALGDPADDING="AES/ECB/PKCS5Padding";

	

	public static byte[] cifrarAsimetrico (byte[] msg, Key key , String algo) 
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, 
			NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher decifrador = Cipher.getInstance(algo); 
		decifrador.init(Cipher.ENCRYPT_MODE, key); 
		return decifrador.doFinal(msg);
	}
	

	public static byte[] DescifrarAsimetrico (byte[] msg, Key key , String algo) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
			IllegalBlockSizeException, BadPaddingException {
		Cipher decifrador = Cipher.getInstance(algo); 
		decifrador.init(Cipher.DECRYPT_MODE, key); 
		return decifrador.doFinal(msg);
	}
	
	public static byte[] digest(byte[] msg, Key key, String algo) throws NoSuchAlgorithmException,
			InvalidKeyException, IllegalStateException, UnsupportedEncodingException {
		Mac mac = Mac.getInstance(algo);
		mac.init(key);

		byte[] bytes = mac.doFinal(msg);
		return bytes;
	}
	
	public static boolean verificarIntegridad(byte[] msg, Key key, String algo, byte [] hash ) throws Exception
	{
		byte [] nuevo = digest(msg, key, algo);
		if (nuevo.length != hash.length) {
			return false;
		}
		for (int i = 0; i < nuevo.length ; i++) {
			if (nuevo[i] != hash[i]) return false;
		}
		return true;
	}

	
	public static SecretKey GenerarLLavesSimetricas(String algoritmo) 
			throws NoSuchAlgorithmException, NoSuchProviderException	{
		int tamLlave = 0;
		if (algoritmo.equals(HMACMD5))
			tamLlave = 64;
		else if (algoritmo.equals(HMACSHA1))
			tamLlave = 64;
		else if (algoritmo.equals(HMACSHA256))
			tamLlave = 64;
	
		
		if (tamLlave == 0) throw new NoSuchAlgorithmException();
		
		KeyGenerator keyGen;
		SecretKey key;
		keyGen = KeyGenerator.getInstance(algoritmo,"BC");
		keyGen.init(tamLlave);
		key = keyGen.generateKey();
		return key;
	}


	public static java.security.cert.X509Certificate generarCertificado(KeyPair pair) throws InvalidKeyException,
	NoSuchProviderException, SignatureException, IllegalStateException, NoSuchAlgorithmException, CertificateException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		certGen.setIssuerDN(new X500Principal("CN=Test Certificate"));
		certGen.setNotBefore(new Date(System.currentTimeMillis() - 10000000));
		certGen.setNotAfter(new Date(System.currentTimeMillis() + 10000000));
		certGen.setSubjectDN(new X500Principal("CN=Test Certificate"));
		certGen.setPublicKey(pair.getPublic());
		certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

		certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
		certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature| KeyUsage.keyEncipherment));
		certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));

		certGen.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(
				new GeneralName(GeneralName.rfc822Name, "test@test.test")));
		return certGen.generate(pair.getPrivate(), "BC") ;
	}


	
	public static KeyPair generarRSAKeyPair() throws NoSuchAlgorithmException {

		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
		kpGen.initialize(1024, new SecureRandom());
		return kpGen.generateKeyPair();
	}

    
	public static byte[] descifrarSimetrico(byte[] llaveSimetrica,byte [] cipheredText, String algs) {
		try {
			Cipher cipher = Cipher.getInstance(ALGDPADDING);
			SecretKey desKey = new SecretKeySpec(llaveSimetrica, algs);
			cipher.init(Cipher.DECRYPT_MODE, desKey);
			byte [] clearText = cipher.doFinal(cipheredText);
			String s3 = new String(clearText);
			return clearText;
		}
		catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
		}
		return null;
	}
	
     
	
	public static byte[] cifrarSimetrico(SecretKey llaveSimetrica,byte[] clearText,String algs) {
		byte [] cipheredText;
		try {
			Cipher cipher = Cipher.getInstance(ALGDPADDING);
			cipher.init(Cipher.ENCRYPT_MODE, llaveSimetrica);
			cipheredText = cipher.doFinal(clearText);
			return cipheredText;
		}
		catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
			e.printStackTrace();
		}
		return null;
	}

	

}
