package principal;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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

	public static final String POSICION = "41 24.2028,2 10.4418";

	public final static String algoritmo1="RSA"; //RSA
	public String algoritmo2="HMACMD5"; //HMACMD5
	public String algoritmo3="AES"; //DES


	public Main()
	{

		try {
			sock = new Socket("localhost",4444);
			w = new PrintWriter(sock.getOutputStream(), true );
			r = new BufferedReader( new InputStreamReader( sock.getInputStream( )) );
		} catch (Exception e) {
			System.out.println("Error iniciando conexión");
			e.printStackTrace();
		}
		protocolo();


	}


	private void protocolo() {

		String recibido = null;


		escribir("HOLA");
		leer();
		escribir("ALGORITMOS:"+algoritmo3+":"+algoritmo1+":"+algoritmo2);
		leer();
		escribir("CERCLNT:");
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance(algoritmo1, "BC");
			keyGen.initialize(1024);
			llaves=keyGen.generateKeyPair();
			byte[] b = Seguridad.generarCertificado(llaves).getEncoded();
			//			System.out.println(Transformacion.transformar(b));
			sock.getOutputStream().write( b);
			sock.getOutputStream().flush();


			String respuesta=leer();
			if(!respuesta.split(":")[0].equals("CERTSRV"))
			{
				cerrar();
				System.out.println("Error, el servidor no reconoció el certificado recibido.");
				return;
			}

			byte []c= new byte[520];

			sock.getInputStream().read(c,0,520);
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

			//System.out.println("parte error");
			InputStream in = new ByteArrayInputStream(c);
			//			System.out.println(Transformacion.transformar(c));
			certificadoServidor = (X509Certificate)certFactory.generateCertificate(in);




			if(certificadoServidor!=null)
			{
				escribir("ESTADO:OK");
			}
			else
			{
				escribir("ESTADO:ERROR");
				System.out.println("No recibió el certificado");
			}

			//Leer data
			//leer();
			respuesta=leer();
			if(!respuesta.split(":")[0].equals("DATA"))
			{
				cerrar();
				System.out.println("Error, no se puede leer la llave cifrada.");
				return;
			}


			respuesta=respuesta.split(":")[1];

			System.out.println(respuesta+".");


			//			byte[]num1ciph= Transformacion.destransformar(respuesta);

			//			String llaveSim=new String(SeguridadEjemploEjemplo.DescifrarAsimetrico(num1ciph, llaves.getPrivate(), algoritmo1));
			//			System.out.println(llaveSim);  


			//			System.out.println("llave: "+llaveSim);

			/////Se descifra la LLAVE SIMETRICA y se envia de nuevo la llave al servidor
			//			byte[] llaveSimet=SeguridadEjemploEjemplo.DescifrarAsimetrico(num1ciph, llaves.getPrivate(), algoritmo1);


//			byte[] llaveCifrada = SeguridadEjemploEjemplo.cifrarAsimetrico(llaveSimet,certificadoServidor.getPublicKey() , algoritmo1);	

			//			String  llaveExtraidaCifrada = Transformacion.transformar(llaveCifrada);


			//			escribir("DATA:" + llaveExtraidaCifrada );

			respuesta=leer();
			if(!respuesta.split(":")[1].equals("OK"))
			{
				cerrar();
				System.out.println("Error, no se pudo reenviar la llave simetrica.");
				return;
			}


//			SecretKey llaveSimetrica = new SecretKeySpec(llaveSimet, algoritmo3);




			//Acá es lo de ACT SE ENVIA LA POSICION Y EL CODIGO hash


			//			String posicion=Transformacion.transformar((SeguridadEjemplo.cifrarSimetrico(llaveSimetrica, POSICION.getBytes(), algoritmo3)));
			//			escribir("ACT1:" + posicion);


			//			String resumenDigital=Transformacion.transformar(SeguridadEjemplo.cifrarAsimetrico(SeguridadEjemplo.digest(POSICION.getBytes(), llaveSimetrica, algoritmo2), llaves.getPrivate(), algoritmo1));
			//			escribir("ACT2:" + resumenDigital);


			recibido= leer();
			if(!recibido.split(":")[1].equals("OK"))
			{
				cerrar();
				System.out.println("Error en posicion, llave simetrica o resumen digital");
				return;
			}				
			else
				System.out.println("Se envió la posicion");
			cerrar();	


		}catch(Exception e){
			e.printStackTrace();
		}





	}

	private void escribir(String string) {
		w.println(string);
		System.out.println(string);

	}


	private String leer() {
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
			// Error cerrando conexión
			e.printStackTrace();
		}
	}

	public static void main(String[] args)
	{
		Main cliente = new Main();
	}

}
