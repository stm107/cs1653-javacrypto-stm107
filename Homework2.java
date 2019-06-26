//sean mizerski
//hw2 cs1653
//stm107
// NOTE: My implementation is based heavily on the BouncyCastle test examples
// These can be found in the bouncy castle source in src/bouncycastle/jce.provider/test/

import java.io.*;
import java.util.*;
import javax.crypto.*;
import java.security.*;
import javax.crypto.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Homework2{

	public static void main(String args[]) throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		// read from the keyboard
		Scanner input = new Scanner(System.in);
		System.out.printf("Please enter some text: ");
		String some_text = input.nextLine();
		aes(some_text);
		blowfish(some_text);
		rsa(some_text, true);
		System.out.printf("Do you want to run the 100 string comparisons (y/n)?: ");
		String comp = input.nextLine();
		switch(comp){
			case "y":
				compareTimes();
			default:
				System.out.printf("Done running program.\n");
		}
		

	}

	private static void aes(String plain_text) throws Exception{

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
		Cipher aes_cipher = Cipher.getInstance("AES/CFB/NoPadding", "BC");

		////////////////
		// encryption //
		////////////////

		aes_cipher.init(aes_cipher.ENCRYPT_MODE, secret_key, iv_param);
		encryted_data = aes_cipher.doFinal(pt_bytes);
		System.out.printf("This is the result of encrypting the input using AES: ");
		print_bytes(encryted_data);
		System.out.printf("\n");


		////////////////
		// decryption //
		////////////////

		aes_cipher.init(aes_cipher.DECRYPT_MODE, secret_key, iv_param);
		decrypted_data = aes_cipher.doFinal(encryted_data);
		String result = new String(decrypted_data);
		System.out.printf("This is the result of decryting the input using AES: " + result + "\n");


	}

	private static void blowfish(String plain_text) throws Exception{

		Random rand = new Random();

		// byte arrays for key, encryption decryption data, and plain text data
		//key must be 128 bits
		byte[] key_bytes = new byte[16];
		byte[] encryted_data, decrypted_data, pt_bytes;
		pt_bytes = plain_text.getBytes();

		// fill with random bytes
		rand.nextBytes(key_bytes);

		// gen blowfish key
		SecretKeySpec secret_key = new SecretKeySpec(key_bytes, "Blowfish");

		// creates blowfish cipher got this from bouncy docs
		Cipher bf_cipher = Cipher.getInstance("Blowfish", "BC");

		////////////////
		// encryption //
		////////////////

		bf_cipher.init(bf_cipher.ENCRYPT_MODE, secret_key);
		encryted_data = bf_cipher.doFinal(pt_bytes);
		System.out.printf("This is the result of encrypting the input using Blowfish: ");
		print_bytes(encryted_data);
		System.out.printf("\n");

		////////////////
		// decryption //
		////////////////

		bf_cipher.init(bf_cipher.DECRYPT_MODE, secret_key);
		decrypted_data = bf_cipher.doFinal(encryted_data);
		String result = new String(decrypted_data);
		System.out.printf("This is the result of decryting the input using BLOWFISH: " + result + "\n");


	}

private static void rsa(String plain_text, boolean run_verify) throws Exception{

		// byte arrays for encryption decryption data, signed data, and plain text data
		byte[] encryted_data, decrypted_data, pt_bytes, signed_data;
		pt_bytes = plain_text.getBytes();
		boolean verified;

		// generate key pairs
		KeyPairGenerator key_pear_gen = KeyPairGenerator.getInstance("RSA", "BC");
		key_pear_gen.initialize(2048); // google says 2048 is good
		KeyPair key_pear = key_pear_gen.generateKeyPair();
		PrivateKey pri_key = key_pear.getPrivate();
		PublicKey lic_key = key_pear.getPublic();

		// creates Rsa cipher got this from bouncy docs
		Cipher RSA_cipher = Cipher.getInstance("RSA", "BC");

		////////////////
		// encryption //
		////////////////

		RSA_cipher.init(RSA_cipher.ENCRYPT_MODE, lic_key);
		encryted_data = RSA_cipher.doFinal(pt_bytes);
		System.out.printf("This is the result of encrypting the input using RSA: ");
		print_bytes(encryted_data);
		System.out.printf("\n");

		////////////////
		// decryption //
		////////////////

		RSA_cipher.init(RSA_cipher.DECRYPT_MODE, pri_key);
		decrypted_data = RSA_cipher.doFinal(encryted_data);
		String result = new String(decrypted_data);
		System.out.printf("This is the result of decryting the input using RSA: " + result + "\n");

		/////////////////////
		// signature stuff //
		/////////////////////

		if(run_verify){
			Signature sign = Signature.getInstance("RSA", "BC");
			sign.initSign(pri_key);
			sign.update(pt_bytes);
			signed_data = sign.sign();

			sign.initVerify(lic_key);
			sign.update(pt_bytes);
			verified = sign.verify(signed_data);
			if (verified) System.out.printf("Very verified!\n");
		}
	}

	// returns a list of 100 random strings
	private static ArrayList<String> generateRandomStrings(){
		// for returning
		ArrayList<String> random_strings = new ArrayList<>();

		for(int i = 0; i < 100; i++){
			// using java's uuid for ease of random generation
			String random_string = UUID.randomUUID().toString();
			random_strings.add(random_string);
		}

		return random_strings;
	}

	private static long aesTime(ArrayList<String> rands) throws Exception{
		long startTime = System.nanoTime();
		for(String s: rands){
			aes(s);
		}
		long stopTime = System.nanoTime();
		return stopTime - startTime;
	}

	private static long bfTime(ArrayList<String> rands) throws Exception{
		long startTime = System.nanoTime();
		for(String s: rands){
			blowfish(s);
		}
		long stopTime = System.nanoTime();
		return stopTime - startTime;
	}

	private static long rsaTime(ArrayList<String> rands) throws Exception{
		long startTime = System.nanoTime();
		for(String s: rands){
			rsa(s, false);
		}
		long stopTime = System.nanoTime();
		return stopTime - startTime;
	}

	private static void compareTimes() throws Exception{
		ArrayList<String> random_strings = generateRandomStrings();
		System.out.printf("Performing 300 encryptions. Go get a snack while you wait...\n\n");
		long aes_time = aesTime(random_strings);
		long bf_time = bfTime(random_strings);
		long rsa_time = rsaTime(random_strings);

		System.out.printf("AES is " + rsa_time/aes_time + " times faster than RSA.\n");
		System.out.printf("Blowfish is " + rsa_time/bf_time + " times faster than RSA.\n");
		System.out.printf("Blowfish is " + aes_time/bf_time + " times faster than AES.\n");
	}

	private static void print_bytes(byte[] to_print){
		for(byte bite: to_print){
			System.out.print(bite);
		}
	}
}

















