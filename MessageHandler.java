import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 * Handles the encryption and decryption of messages
 * as well as verification of Message Authentication Codes
 * 
 *
 */
public class MessageHandler {
	
	private SecretKey key;
	private Cipher cipher;
	
	
	/**
	 * Constructor that stores the shared key from the Exchange 
	 * @param key, shared AES-256 bit symmetric key
	 */
	public MessageHandler(SecretKey key)
	{
		this.key = key;
		try {
			this.cipher = Cipher.getInstance("AES");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			System.out.println("Error constructing message handler");
			e.printStackTrace();
		}
	}
	
	
	
	/**
	 * Encrypts the message using the shared secret key
	 * @param message, data to be encrypted
	 * @return the encrypted message
	 */
	public byte[] encryptMessage(byte[] message)
	{
		byte[] handled_message = null;
		
		try {
			cipher.init(Cipher.ENCRYPT_MODE, key);
			handled_message = cipher.doFinal(message);
			
			
			
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			System.out.println("Error encrypting message");
			e.printStackTrace();
		}
		
		
		
		return handled_message;
	}
	
	/**
	 * Returns decrypted message
	 * @param message, encrypted message
	 * @return decrypted message
	 */
	public byte[] decryptMessage(byte[] message)
	{
		byte[] handled_message = null;
		
		try {
			cipher.init(Cipher.DECRYPT_MODE, key);
			handled_message = cipher.doFinal(message);
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			System.out.println("Error decrypting message");
			e.printStackTrace();
		}
		
		
		
		return handled_message;
	}
	
	/**
	 * Computes the HmacSHA256 using the shared secret key
	 * @param message, raw message
	 * @return HMAC in byte[] 
	 */
	public byte[] produceMAC(byte[] message)
	{
		byte[] authenticationCode = null;
		
		try {
			
			Mac HMAC = Mac.getInstance("HmacSHA256");
			HMAC.init(key);
			authenticationCode = HMAC.doFinal(message);
			
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			System.out.println("Error producing HMAC");
			e.printStackTrace();
		}
		
		return authenticationCode;
	}

	
	/**
	 * Verifies the HMAC sent 
	 * @param message, message sent
	 * @param HMAC, HMAC sent
	 * @return true if able to reproduce the same HMAC, false otherwise
	 */
	public boolean verifyMAC(byte[] message, byte[] HMAC)
	{
		
		return Arrays.toString(produceMAC(message)).equals(Arrays.toString(HMAC));
	}
	

}
