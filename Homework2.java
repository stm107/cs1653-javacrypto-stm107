//sean mizerski
//hw2 cs1653
//stm107

import java.io.*;
import java.util.*;
import javax.crypto.*;
import java.security.*;
import javax.crypto.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Homework2{

	public static void main(String args[])
	{
		// read from the keyboard
		Scanner input = new Scanner(System.in);
		System.out.printf("Please enter some text: ");
		String some_text = input.nextLine();
	}

	private static void AES(String plain_text) throws Exception{

		Random rand = new Random();

		// byte arrays for key, iv, encryption decryption data, and plain text data
		// iv and key must be 128 bits
		byte[] key_bytes = new byte[16];
		byte[] iv_bytes = new byte[16];
		byte[] encryted_data, decrypted_data, pt_bytes;
		pt_bytes = plain_text.getBytes();

		// fill with random bytes
		rand.nextBytes(key_bytes);
		rand.nextBytes(iv_bytes);

		// generates the iv 
		IvParameterSpec iv_param = new IvParameterSpec(iv_bytes);

		// gen aes key
		SecretKeySpec secret_key = new SecretKeySpec(key_bytes, "AES");

		// creates aes cipher got this from bouncy docs
		Cipher aes_cipher = Cipher.getInstance("AES", "BC");

		////////////////
		// encryption //
		////////////////

		aes_cipher.init(aes_cipher.ENCRYPT_MODE, secret_key, iv_param);
		encryted_data = aes_cipher.doFinal(pt_bytes);

		////////////////
		// decryption //
		////////////////

		aes_cipher.init(aes_cipher.DECRYPT_MODE, secret_key, iv_param);
		decrypted_data = aes_cipher.doFinal(encryted_data);
		String result = new String(decrypted_data);
		System.out.printf("This is the result of encrypting and then decryting the input using AES: " + result + "/n");


	}

}