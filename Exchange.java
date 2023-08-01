
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import java.security.*;
import java.security.spec.InvalidKeySpecException;

import java.security.spec.X509EncodedKeySpec;

/**
 * Stores Client/Server cryptographic keys and provides methods for manipulating them
 *
 */
public class Exchange {
	
	private KeyPair myKeys;
	private PublicKey otherKey;
	private byte[] otherKeyEncoded;
	private SecretKey symmetricKey;
	
	
	
	/**
	 * Default Constructor, generates a 2048-bit RSA KeyPair and allocates space for 
	 * a shared symmetric key
	 * 
	 */
	public Exchange()
	{
		generateKeyPair();
		otherKeyEncoded = new byte[294];
	
	}
	
	
	/**
	 * Generates a KeyPair used for Authentication
	 */
	private void generateKeyPair()
	{
		//make a keyGenerator based on RSA
		KeyPairGenerator keyGenerator;
		try {
			SecureRandom secureRandom = new SecureRandom();
			keyGenerator = KeyPairGenerator.getInstance("RSA");
			keyGenerator.initialize(2048, secureRandom);
			myKeys = keyGenerator.generateKeyPair();
			
			
		
		
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error Generating KeyPair");
			e.printStackTrace();
		}
				
				
	}
	
	
	
	/**
	 * Used to retrieve Public Key for transport
	 * 
	 * @return the PublicKey from your keyPair
	 */
	public byte[] getPublicKey()
	{
		return this.myKeys.getPublic().getEncoded();
	}
	
	
	/**
	 * Take a byte[] representation of the other person's public key and store it as a PublicKey object
	 * Works only for RSA keys
	 */
	public void storeOtherPublicKey(byte[] encodedKey)
	{
		this.otherKeyEncoded = encodedKey;
		
		
		
		KeyFactory factory;
		
		try {
				
			factory = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec PubKeySpec = new X509EncodedKeySpec(encodedKey); 
			this.otherKey = factory.generatePublic(PubKeySpec);
			
			
			
			
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		
		
		


	}

	
	/**
	 * Makes a shared Secret Key for Symmetric Cryptographic communication
	 */
	public void makeSymmetricKey()
	{
		SecureRandom securerandom = new SecureRandom();
		
		KeyGenerator keygenerator;
		try {
			keygenerator = KeyGenerator.getInstance("AES");
			keygenerator.init(256, securerandom);

			symmetricKey = keygenerator.generateKey();
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		
	}
		
	/**
	 * Encrypts the shared Secret Key with the other person's public key	
	 * 
	 * @return byte[] representation of encrypted-encoded shared Secret Key
	 */
	public byte[] encryptSymmetricKey()
	{
		
		byte[] encryptedKey = null;
		
        
		try {
			
			Cipher cipher = Cipher.getInstance("RSA");
			
			//encrypt with their public
			cipher.init(Cipher.ENCRYPT_MODE, otherKey);
			encryptedKey = cipher.doFinal(symmetricKey.getEncoded());
	        
			
			
			
	        
	        
	        
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return encryptedKey;
        
		
        
        
       
	}

	/**
	 * Takes the encoded byte[] representations of a shared key and 
	 * makes a SecretKey object from it
	 * @param key, encoded shared key
	 */
	public void storeSymmetricKey(byte[] key)
	{
		//Get encoded key from encrypted byte[]
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, myKeys.getPrivate());
			
			byte[] decryptedKey = cipher.doFinal(key);
	        
	        
	        this.symmetricKey = new SecretKeySpec(decryptedKey, "AES");
	        
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        
	}
	
	/**
	 * Returns the shared SecretKey
	 * @return this.symmetricKey
	 */
	public SecretKey getSharedKey()
	{
		return this.symmetricKey;
	}
	
	
	
	/*
	Hybrid encryption - asymmetric encrption to facilitate a key exchange and secret key used with symmetric encryption for bulk data
	- each person generates a public-private key pair
	- one person generates a single extra key
	- encrpyts that key with the other persons public key and sends it publicly to the other person
	- the other person can now decrypt the key with their private key
	- both parties now how a shared symmetric key
    */
	
	
	
	
}
