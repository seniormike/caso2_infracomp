package LogisticaSeguridadAeroportuaria;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;


/**
 * 	 @authors
 * - Minh Huy Mattieu Iung
 * - Miguel Angel Puentes
 * - Kelvin Santiago Estupinan
 */

public class Main
{
	public BufferedReader read;
	public PrintWriter write;
	public KeyPair keys;
	public Socket socket;
	public X509Certificate serverCertificate;


	/**
	 * Algoritmos
	 */
	public String algoritmo1 = "RSA"; //RSA
	public String algoritmo2 = "AES"; //AES
	public String algoritmo3 = "HMACMD5"; //HMACMD5


	/**
	 * Método Constructor de la clase.
	 */
	public Main()
	{

		/**
		 * Se configuran los parametros del socket para permitir la comunicación con el servidor.
		 */
		try {
			socket = new Socket("localhost",5555);
			write = new PrintWriter(socket.getOutputStream(),true);
			read = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		}
		catch (Exception e)
		{
			System.out.println("Error al conectarse");
			e.printStackTrace();
		}
		protocole();
	}

	/**
	 * Método que representa y contiene el protocolo de comunicación entre
	 * el cliente y el servidor con seguridad.
	 */
	private void protocole()
	{
		toWrite("HOLA");
		toRead();
		toWrite("ALGORITMOS:"+algoritmo2+":"+algoritmo1+":"+algoritmo3);
		toRead();
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance(algoritmo1, "BC");
			keyGen.initialize(1024);
			keys = keyGen.generateKeyPair();
			byte[] b = generarCertificado(keys).getEncoded();
			String transformado = toStringHex(b);
			toWrite(transformado);

			String respuesta = toRead();

			if(!respuesta.equals("OK"))
			{
				closeGeneral();
				System.out.println("Error, el servidor no reconoció el certificado recibido.");
				return;
			}

			String certificado = toRead();

			byte [] arrr = new byte[520];
			arrr = toArrayByte(certificado);

			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			InputStream in = new ByteArrayInputStream(arrr);

			serverCertificate = (X509Certificate)certFactory.generateCertificate(in);


			if(serverCertificate != null)
			{
				toWrite("OK");
			}
			else
			{
				toWrite("ERROR");
				System.out.println("No se recibió el certificado");
			}

			String llaveSimetrica = toRead();

			byte[] descencriptada = AssymetricDecipher(toArrayByte(llaveSimetrica),keys,"RSA");

			byte [] cifrada = AssymetricCipher(descencriptada, serverCertificate.getPublicKey(), "RSA");

			String cifradaEnString = toStringHex(cifrada);

			toWrite(cifradaEnString);

			toRead();


			String consultation = (int)(Math.random()*10000)+"";

			SecretKey llaveN = new SecretKeySpec(descencriptada, 0, descencriptada.length,algoritmo2);

			Cipher c = Cipher.getInstance(algoritmo2); 
			c.init(Cipher.ENCRYPT_MODE, llaveN); 
			byte[] answ = c.doFinal(consultation.getBytes());
			String answString = toStringHex(answ);
			toWrite(answString);

			Mac hmac = Mac.getInstance(algoritmo3);
			hmac.init(llaveN);
			byte[] bMac = hmac.doFinal(consultation.getBytes());
			String hMacString = toStringHex(bMac);

			toWrite(hMacString);

			toRead();

		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}

	/**
	 * Método que se encarga de enviar el string dado por parametro al servidor.
	 * Además, imprime en consola.
	 * @param string
	 */
	private void toWrite(String string)
	{
		write.println(string);
		System.out.println(string);
	}
	/**
	 * Método que se encarga de leer el string que se recibe del servidor.
	 * Además, imprime el mensaje en consola.
	 * @param string
	 */
	private String toRead()
	{
		System.out.println("leyendo");
		String m="";
		try {
			m = read.readLine();
			System.out.println(m);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return m;
	}

	/**
	 * Método que se encarga de closeGeneral todas los canales de comunicación en caso de que haya
	 * un error en el protocolo.
	 */
	private void closeGeneral() 
	{
		try {
			write.close( );
			read.close( );
			socket.close( );
		} catch (IOException e)
		{
			e.printStackTrace();
		}
	}

	/**
	 * Método que convierte un arreglo de bytes a un string utilizando base hexadecimal.
	 * @param array
	 * @return
	 */
	public String toStringHex(byte[] a)
	{
		return DatatypeConverter.printHexBinary(a);
	}

	/**
	 * Método que convierte un string a un arreglo de bytes utilizando base hexadecimal.
	 * @param array
	 * @return
	 */
	public byte[] toArrayByte(String s)
	{
		return DatatypeConverter.parseHexBinary(s);
	}

	/**
	 * Método que se encarga de realizar un cifrado asimentrico utilizando los parametros que recibe.
	 * @param msg
	 * @param keyPair que contiene un par de llaves.
	 * @param alg
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] AssymetricDecipher(byte[] msg, KeyPair key , String a) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,IllegalBlockSizeException, BadPaddingException
	{
		Cipher d = Cipher.getInstance(a); 
		d.init(Cipher.DECRYPT_MODE, key.getPrivate()); 
		return d.doFinal(msg);
	}
	
	/**
	 * Método que se encarga de realizar un cifrado asimentrico utilizando los parametros que recibe.
	 * @param msg
	 * @param keyPair que contine un par de llaves.
	 * @param algo
	 * @return
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public static byte[] AssymetricCipher(byte[] msg, KeyPair key , String a) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,NoSuchAlgorithmException, NoSuchPaddingException
	{
		Cipher d = Cipher.getInstance(a); 
		d.init(Cipher.ENCRYPT_MODE, key.getPublic()); 
		return d.doFinal(msg);
	}
	
	/**
	 * Método que se encarga de realizar un cifrado asimentrico utilizando los parametros que recibe. 
	 * @param msg
	 * @param PublicKey que representa una llavepublica.
	 * @param algo
	 * @return
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public static byte[] AssymetricCipher(byte[] msg, PublicKey key , String a) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,NoSuchAlgorithmException, NoSuchPaddingException
	{
		Cipher decifrador = Cipher.getInstance(a); 
		decifrador.init(Cipher.ENCRYPT_MODE, key); 
		return decifrador.doFinal(msg);
	}

	/**
	 * Método que se encarga de genera un certificado a partir de el par de llaves que recibe como parametro.
	 * @param pair
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchProviderException
	 * @throws SignatureException
	 * @throws IllegalStateException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 */
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

		certGen.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test")));
		return certGen.generate(pair.getPrivate(), "BC") ;
	}
	/**
	 * Método Main que se encarga de inicializar la comunicacion entre el cliente y el servidor.
	 * @param args
	 */
	public static void main(String[] args)
	{
		Main client = new Main();
	}

}
