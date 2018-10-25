package principal;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.sun.corba.se.impl.oa.poa.ActiveObjectMap.Key;
import com.sun.org.apache.xalan.internal.xsltc.compiler.sym;

import principal.Seguridad;
//import utils.Transformacion;

public class Main {

	public BufferedReader r;
	public PrintWriter w;
	public KeyPair llaves;
	public Socket sock;
	public X509Certificate certificadoServidor;


	public final static String algoritmo1="RSA"; //RSA
	public String algoritmo2="HMACMD5"; //HMACMD5
	public String algoritmo3="AES"; //DES


	public Main()
	{

		try {
			sock = new Socket("localhost",5555);
			w = new PrintWriter(sock.getOutputStream(), true );
			r = new BufferedReader( new InputStreamReader( sock.getInputStream( )) );
		} catch (Exception e) {
			System.out.println("Error iniciando conexi�n");
			e.printStackTrace();
		}
		protocolo();


	}


	private void protocolo()
	{

		String recibido = null;

		escribir("HOLA");
		leer();
		escribir("ALGORITMOS:"+algoritmo3+":"+algoritmo1+":"+algoritmo2);
		leer();
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance(algoritmo1, "BC");
			keyGen.initialize(1024);
			llaves = keyGen.generateKeyPair();
			byte[] b = Seguridad.generarCertificado(llaves).getEncoded();
			String transformado = toHexString(b);
			escribir(transformado);

			String respuesta = leer();
			System.out.println("Resp" + respuesta);

			if(!respuesta.equals("OK"))
			{
				cerrar();
				System.out.println("Error, el servidor no reconoci� el certificado recibido.");
				return;
			}

			String certificado = leer();
			System.out.println("Cert" + certificado);

			byte [] arrr = new byte[520];
			arrr = toByteArray(certificado);

			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			InputStream in = new ByteArrayInputStream(arrr);

			certificadoServidor = (X509Certificate)certFactory.generateCertificate(in);


			if(certificadoServidor != null)
			{
				escribir("OK");
			}
			else
			{
				escribir("ERROR");
				System.out.println("No recibi� el certificado");
			}

			String llaveSimetrica = leer();
			System.out.println("llaveSimetrica: "+ llaveSimetrica);



			byte[] descencriptada = DescifrarAsimetrico(toByteArray(llaveSimetrica),llaves,"RSA");

			byte [] cifrada = cifrarAsimetrico(descencriptada, certificadoServidor.getPublicKey(), "RSA");

			String cifradaEnString = toHexString(cifrada);

			escribir(cifradaEnString);

			String resp = leer();

			String consulta = "35";

			SecretKey llaveN = new SecretKeySpec(descencriptada, 0, descencriptada.length,algoritmo3);

			Cipher c = Cipher.getInstance(algoritmo3); 
			c.init(Cipher.ENCRYPT_MODE, llaveN); 
			byte[] answ = c.doFinal(consulta.getBytes());
			String answString = toHexString(answ);
			escribir(answString);

			Mac hmac = Mac.getInstance(algoritmo2);
			hmac.init(llaveN);
			byte[] bMac = hmac.doFinal(consulta.getBytes());
			String hMacString = toHexString(bMac);

			escribir(hMacString);

			String r = leer();



		}catch(Exception e)
		{
			e.printStackTrace();
		}



	}

	private void escribir(String string)
	{
		w.println(string);
		System.out.println(string);
	}

	public String toHexString(byte[] array)
	{
		return DatatypeConverter.printHexBinary(array);
	}
	public byte[] toByteArray(String a)
	{
		return DatatypeConverter.parseHexBinary(a);
	}

	public static byte[] DescifrarAsimetrico (byte[] msg, KeyPair key , String alg) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,IllegalBlockSizeException, BadPaddingException
	{
		Cipher decifrador = Cipher.getInstance(alg); 
		decifrador.init(Cipher.DECRYPT_MODE, key.getPrivate()); 
		return decifrador.doFinal(msg);
	}
	public static byte[] cifrarAsimetrico (byte[] msg, KeyPair key , String algo) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,NoSuchAlgorithmException, NoSuchPaddingException
	{
		Cipher decifrador = Cipher.getInstance(algo); 
		decifrador.init(Cipher.ENCRYPT_MODE, key.getPublic()); 
		return decifrador.doFinal(msg);
	}

	public static byte[] cifrarAsimetrico (byte[] msg, PublicKey key , String algo) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,NoSuchAlgorithmException, NoSuchPaddingException
	{
		Cipher decifrador = Cipher.getInstance(algo); 
		decifrador.init(Cipher.ENCRYPT_MODE, key); 
		return decifrador.doFinal(msg);
	}


	private String leer()
	{
		System.out.println("leyendo");
		String m="";
		try {

			m=r.readLine();
			System.out.println(m);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return m;
	}


	private void cerrar() 
	{
		try {
			w.close( );
			r.close( );
			sock.close( );
		} catch (IOException e) {
			// Error cerrando conexi�n
			e.printStackTrace();
		}
	}

	public static void main(String[] args)
	{
		Main cliente = new Main();
	}

}
