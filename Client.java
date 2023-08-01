import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Scanner;


/**
 * Handles the Client side of the interaction
 * 		-key exchange with server
 * 		-input from server
 * 		-output from client
 *
 */
public class Client{

	private static Socket socket;
	private static DataInputStream inputFromServer;
	private static DataOutputStream outputFromClient;
	private static Scanner keyboard;
	private static Exchange exchange;
	private static MessageHandler crypto;
	
	
	/**
	 * Initializes variables and key exchange. Starts input and output threads.
	 * @param port, port number that the user wants to open a conversation on
	 */
	private static void initConversation(String serverID, int port)
	{
		
		try {
			
			socket = new Socket(serverID, port);
			
			
			
			
			
			inputFromServer = new DataInputStream(socket.getInputStream());
			outputFromClient = new DataOutputStream(socket.getOutputStream());
			
			//call function to generate keys and swap symmetric key
			//make keyPair
			exchange = new Exchange();
			keyExchange();
						
	
			
			//initialize cryptographic functions
			crypto = new MessageHandler(exchange.getSharedKey());
			
			//start output thread to server
			startServerInput();
			
			//start input thread from server
			startClientOutput();
		
		
		
		
		}catch(java.net.ConnectException e) {
			System.out.println("Server Offline ---- No Conversation");
			// TODO ask user if they want to try another connection
			
			
		} catch (UnknownHostException e) {
			System.out.println("ServerID unreachable");
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		//TODO learn how to close the connection.
		
		//closeConnection();
		
		
		
		
	}
	
	/**
	 * Facilitates the generation of a public-private key pair, as
	 * well as an encrypted symmetric key exchange
	 */
	private static void keyExchange()
	{
		/*
		 * 1. receive public key from server
		 * 2. send public key to server
		 * 3. make symmetric key, encode with server pub, send to server
		 */
		
		
		
		//receive public key from server
		byte[] serverPublicKey = null;
		int encodedKeyLength;
		
		byte[] clientPubKey = exchange.getPublicKey();
		
		
		try {
			encodedKeyLength = inputFromServer.readInt();
			serverPublicKey = new byte[encodedKeyLength];
			inputFromServer.readFully(serverPublicKey);
			//store public key in exchange
			exchange.storeOtherPublicKey(serverPublicKey);
			
			// send public key to the server
			outputFromClient.writeInt(clientPubKey.length);
			outputFromClient.write(clientPubKey, 0, clientPubKey.length);
			
			
			//make symmetric key, encode with their public key, and send
			exchange.makeSymmetricKey();
			byte[] symmetricKeyEncrypted = exchange.encryptSymmetricKey();
			outputFromClient.writeInt(symmetricKeyEncrypted.length);
			outputFromClient.write(symmetricKeyEncrypted, 0, symmetricKeyEncrypted.length);
			
		} catch (IOException e) {
			closeConnection();
			e.printStackTrace();
		}
		
		
	
		
		
		
		
	}
	
	
	/**
	 * Starts and maintains a thread for receiving messages from the server
	 */
	private static void startServerInput()
	{
		
		new Thread( new Runnable()
				{

					@Override
					public void run() {
						
						try
						{
							
							
							while(true)
							{
								//receive encrypted message
								byte[] encryptedClientMSG = null;
								
								
								int lengthMSG = inputFromServer.readInt();
											
								encryptedClientMSG = new byte[lengthMSG];
								
								inputFromServer.readFully(encryptedClientMSG);
								
								//decrypt message
								byte[] decryptedMessage = crypto.decryptMessage(encryptedClientMSG);
								
								
								//receive HMAC message
								byte[] clientHMAC = null;
								
								
								int lengthHMAC = inputFromServer.readInt();
											
								clientHMAC = new byte[lengthHMAC];
								
								inputFromServer.readFully(clientHMAC);
								
								//verify HMAC
								
								if( crypto.verifyMAC(decryptedMessage, clientHMAC) )
								{
									System.out.println("Server: " + new String(decryptedMessage));
								}
								else
								{
									System.out.println("Message Tampered...Terminate Connection");
									closeConnection();
								}
									
								
								
								
								
								
								
								
								
								
								
								
								
							}
							
							
							
						}catch(IOException e)
						{
							closeConnection();
						}
						
						
					}
				}).start();
	}
		
	
	/**
	 * Starts and maintains a thread for sending messages to the client
	 */
	private static void startClientOutput()
	{
		
				new Thread( new Runnable()
						{

							@Override
							public void run() {
								String clientMessage = "";
								try
								{
									while(true)
									{
										
										clientMessage = keyboard.nextLine();
										
										
										
										byte[] message = clientMessage.getBytes();
										
										
										//encrypt message
										byte[] encryptedMessage = crypto.encryptMessage(message);
										
										outputFromClient.writeInt(encryptedMessage.length);
										outputFromClient.write(encryptedMessage, 0, encryptedMessage.length);
										
										//make and send HMAC
										byte[] HMAC = crypto.produceMAC(message);
										
										
										
										outputFromClient.writeInt(HMAC.length);
										outputFromClient.write(HMAC, 0, HMAC.length);
										
									}
									
									
									
								}catch(IOException e)
								{
									closeConnection();
								}

								
							}
						}).start();
	}
	
	
	/**
	 * Gets port number from user and calls initConversation()
	 * @param args, not used
	 */
	public static void main(String args[])
	{
		
		//input device from client
		keyboard = new Scanner(System.in);
		String serverID;
		int port;
		
		//ask for serverID and port number
		System.out.println("Welcome to ChatGuard");
		
		System.out.println("Enter ServerID: ");
		serverID = keyboard.nextLine();
		// TODO: check that serverID is valid
		// 		??Handled in initCommunication??
		
		
		System.out.println("Enter Port Number: ");
		port = keyboard.nextInt();
		// TODO: check that port number is valid
		
		
		//initialize conversation between client and server
		initConversation(serverID, port);
		
		// NOTE if port is in use a BindException will be thrown and you need to enter cmd to kill the pid
		
		

		
	}
	
	/**
	 * Closes socket and character streams
	 */
	private static void closeConnection()
	{
		try {
			if(socket != null && !socket.isClosed())
			{
				socket.close();
			}
			if(inputFromServer != null)
			{
				inputFromServer.close();
			}
			if(outputFromClient != null)
			{
				outputFromClient.close();
			}
			
			System.out.println("Connection Closed.....Good Bye");
			System.exit(0);
			
		}catch(IOException e)
		{
			System.out.println("Error closing connection...");
			e.printStackTrace();
		}
		
		
		
		
		
		
		
		
		
		
		
		
	}
	
}
