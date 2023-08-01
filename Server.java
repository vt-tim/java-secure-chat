
import java.io.*;
import java.net.*;
import java.net.UnknownHostException;
import java.util.Scanner;

/**
 * Handles the Server side of the interaction
 * 		-key exchange with client
 * 		-input from client
 * 		-output from server
 *
 */
public class Server{

	
	
	private static Socket socket;
	private static DataInputStream inputFromClient;
	private static DataOutputStream outputFromServer;
	private static Scanner keyboard;
	private static ServerSocket server;
	private static Exchange exchange;
	private static MessageHandler crypto;
	
	
	/**
	 * Initializes variables and key exchange. Starts input and output threads.
	 * @param port, port number that the user wants to open a conversation on
	 */
	private static void initConversation(int port)
	{
		
		
		try {
			
			
			
			
			//open communication to and from server
			server = new ServerSocket(port);
			socket = server.accept();
			

			
			inputFromClient = new DataInputStream(socket.getInputStream());
			outputFromServer = new DataOutputStream(socket.getOutputStream());
			
			//call function to generate keys and swap symmetric key
			exchange = new Exchange();
			keyExchange();
			
			
			//initialize cryptographic functions
			crypto = new MessageHandler(exchange.getSharedKey());
			
			//start input thread from client
			startClientInput();
			
			//start output thread from server
			startServerOutput();
		
		
		
		
		
		}catch(java.net.ConnectException e) {
			System.out.println("Server Offline ---- No Conversation");
			// TODO ask user if they want to try another connection
			e.printStackTrace();
			
			
		} catch (UnknownHostException e) {
			System.out.println("ServerID unreachable");
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		
		
		
		
		
	}
	
	/**
	 * Facilitates the generation of a public-private key pair, as
	 * well as an encrypted symmetric key exchange
	 */
	private static void keyExchange()
	{
		// TODO put all exchange business in Exchange class
		
		
		/*
		 * 1. send encoded server public key to client
		 * 2. receive public key from client
		 * 3. receive, decode and store symmetric key
		 */
		
		
		
		//send encoded server public key to client
		byte[] serverPubKey = exchange.getPublicKey();
		
		byte[] key = null;
		int encodedKeyLength;
		
		
		try {
			outputFromServer.writeInt(serverPubKey.length);
			outputFromServer.write(serverPubKey, 0, serverPubKey.length);
			
			//receive public key from client
			encodedKeyLength = inputFromClient.readInt();
			key = new byte[encodedKeyLength];
			inputFromClient.readFully(key);
			
			//store public key in exchange
			exchange.storeOtherPublicKey(key);
			
			
			//get symmetric key from the client
			encodedKeyLength = inputFromClient.readInt();
			key = new byte[encodedKeyLength];
			inputFromClient.readFully(key);
			//store symmetric key in exchange
			exchange.storeSymmetricKey(key);
			
			
		} catch (IOException e) {
			closeConnection();
			e.printStackTrace();
		}
		
		
		
		
		
		
		

		
		
		
		
		
		
		
	}

	/**
	 * Starts and maintains a thread for receiving messages from the client
	 */
	private static void startClientInput()
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
								
								
								int lengthMSG = inputFromClient.readInt();
											
								encryptedClientMSG = new byte[lengthMSG];
								
								inputFromClient.readFully(encryptedClientMSG);
								
								//decrypt message
								byte[] decryptedMessage = crypto.decryptMessage(encryptedClientMSG);
								
								
								//receive HMAC message
								byte[] clientHMAC = null;
								
								
								int lengthHMAC = inputFromClient.readInt();
											
								clientHMAC = new byte[lengthHMAC];
								
								inputFromClient.readFully(clientHMAC);
								
								
								
								//verify HMAC
								

								if( crypto.verifyMAC(decryptedMessage, clientHMAC) )
								{
									System.out.println("Client: " + new String(decryptedMessage));
								}
								else
								{
									System.out.println("Message Tampered...Terminating Connection");
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
	private static void startServerOutput()
	{
		
		
				new Thread( new Runnable()
						{

							@Override
							public void run() {
								String serverMessage = "";
								try
								{
									while(true)
									{
										serverMessage = keyboard.nextLine();
										
										
										
										byte[] message = serverMessage.getBytes();
										
										
										//encrypt message
										byte[] encryptedMessage = crypto.encryptMessage(message);
										
										outputFromServer.writeInt(encryptedMessage.length);
										outputFromServer.write(encryptedMessage, 0, encryptedMessage.length);
										
										//make and send HMAC
										byte[] HMAC = crypto.produceMAC(message);
										
										outputFromServer.writeInt(HMAC.length);
										outputFromServer.write(HMAC, 0, HMAC.length);
									}
									
									
									
								}catch(IOException e)
								{
									e.printStackTrace();
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
		
		int port;
		
		//ask for serverID and port number
		System.out.println("Welcome to ChatGuard");
		
		
		
		
		System.out.println("Enter Port Number: ");
		port = keyboard.nextInt();
		// TODO: check that port number is valid
		
		
		//initialize conversation between client and server
		initConversation(port);
		
		

		
	}
	
	/**
	 * Closes socket and byte streams
	 */
	private static void closeConnection()
	{
		try {
			if(socket != null && !socket.isClosed())
			{
				socket.close();
			}
			if(inputFromClient != null)
			{
				inputFromClient.close();
			}
			if(outputFromServer != null)
			{
				outputFromServer.close();
			}
			if( server != null && !server.isClosed())
			{
				server.close();
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
