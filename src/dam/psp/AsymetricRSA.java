package dam.psp;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class AsymetricRSA {
	
	public static final String ALG = "RSA";
	
	public static String encriptar(String mensaje, KeyPair clave) throws Exception{
		Cipher rsaCifrador =Cipher.getInstance(ALG);
		rsaCifrador.init(Cipher.ENCRYPT_MODE,clave.getPublic());
		byte[] criptogramaenBytes=Base64.getEncoder().encode(rsaCifrador.doFinal(mensaje.getBytes("UTF-8")));
		
		
		return new String(criptogramaenBytes);
	}
	
	public static String desencriptar(String criptograma, KeyPair clave) throws Exception{
		Cipher rsaCifrador =Cipher.getInstance(ALG);
		rsaCifrador.init(Cipher.DECRYPT_MODE,clave.getPrivate());
		byte[] mensajeenBytes=Base64.getDecoder().decode(criptograma.getBytes("UTF-8"));
		
		
		return new String(rsaCifrador.doFinal(mensajeenBytes));
	}
	
	public static void mostrarInfoClave(KeyPair clave) throws Exception{
		KeyFactory factoria= KeyFactory.getInstance(ALG);
		
		RSAPublicKeySpec partepublica=factoria.getKeySpec(clave.getPublic(), RSAPublicKeySpec.class);
		
		RSAPrivateKeySpec partePrivada=factoria.getKeySpec(clave.getPrivate(),RSAPrivateKeySpec.class);
		
		System.out.println("clave publica");
		System.out.println("Modulus: "+partepublica.getModulus());
		System.out.println("Exponentus: "+partepublica.getPublicExponent());
		
		System.out.println("clave privada");
		System.out.println("Modulus: "+partePrivada.getModulus());
		System.out.println("Exponentus: "+partePrivada.getPrivateExponent());
		
	}
	
	public static void main(String[] args) {
		String mensaje="La que ha liao el Paco";
		
		try{
			System.out.println("obteniendo el generador de claves RSA");
			KeyPairGenerator keygen=KeyPairGenerator.getInstance(ALG);
			System.out.println("Generando el par de claves RSA");
			KeyPair clave= keygen.generateKeyPair();
			System.out.println("Informacion de la clave generada");
			mostrarInfoClave(clave);
			String criptograma=encriptar(mensaje,clave);
			System.out.println("mensaje cifrado "+criptograma);
			System.out.println("Mensaje descifrado\n "+desencriptar(criptograma, clave));
			
		}catch (Exception e){}
		
	}
}
