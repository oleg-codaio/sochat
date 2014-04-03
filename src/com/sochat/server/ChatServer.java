package com.sochat.server;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;

import com.google.common.util.concurrent.AbstractExecutionThreadService;
import com.sochat.server.db.UserDatabase;
import com.sochat.shared.Constants;
import com.sochat.shared.Constants.MessageType;
import com.sochat.shared.Utils;
import com.sochat.shared.io.StandardUserIO;
import com.sochat.shared.io.UserIO;

/**
 * Class that contains the chat server, which is responsible for containing the
 * list of credentials for valid users.
 * 
 * Note that for the specifications of this project, this server keeps its
 * "database" in memory. If the server is restarted then its state will be lost.
 * 
 * @author Oleg, Saba
 */
public class ChatServer extends AbstractExecutionThreadService {

    /**
     * The server's private key.
     */
    private final PrivateKey mPrivateKey;

    /**
     * The socket the server uses to listen for a particular port.
     */
    private final DatagramSocket mSocket;

    /**
     * The port on which this chat server is listening.
     */
    private final int mPort;

    /**
     * Create a buffer that will be used for sending/receiving UDP packets.
     */
    private final byte[] mBuffer = new byte[Constants.MAX_MESSAGE_LENGTH];

    /**
     * The logger this server will use to print messages (or save somewhere for
     * unit tests).
     */
    private final UserIO mLogger;

    /**
     * Our user database.
     */
    private final UserDatabase mDb = new UserDatabase();

    private String userlist = "List of currently connected users: \n";
    
    /**
     * Creates a new chat server running on the specified port.
     * 
     * @param port
     * @param logger
     *            the logger to use to save messages
     * @throws IOException
     *             Thrown if there was an issue connecting to the socket.
     * @throws GeneralSecurityException
     */
    public ChatServer(int port, UserIO logger) throws IOException, GeneralSecurityException {
        mPrivateKey = ServerPrivateKey.getServerPrivateKey();
        mLogger = logger;
        mPort = port;
        mSocket = new DatagramSocket(mPort);
    }

    @Override
    protected void startUp() throws Exception {
        mLogger.logMessage("Starting SOChat Server...");
        mLogger.logMessage("Running on " + mSocket.getLocalAddress() + ":" + mSocket.getLocalPort() + "...");
        mLogger.logMessage("Server initialized...");
    }

    public boolean authenticate (String uname, String pword) {
    	
    	boolean result = false;

    	if (user1.get(0).equals(uname)) { 
    	if (user1.get(1).equals(pword)) { result = true; } }
    	
    	if (user2.get(0).equals(uname)) {
    	if (user2.get(1).equals(pword)) { result = true; } }
    	
    	if (user3.get(0).equals(uname)) {
    	if (user3.get(1).equals(pword)) { result = true; } }
    	
    	if (user4.get(0).equals(uname)) {
    	if (user4.get(1).equals(pword)) { result = true; } }
    	
    	if (user5.get(0).equals(uname)) {
    	if (user5.get(1).equals(pword)) { result = true; } }
    	
    	return result;    
    }
    
    static String beforespace (String str) { 
    	int count = 0; 
    	String result = ""; 
    	for (int x=0; x<str.length()-5; x++) { 
    	if (str.charAt(x) == ' ')  break; 
    	else { 
    	count = count + 1; 
    	result = result.concat(str.substring(x, x+1)); } } 
    	return result;
    }
    
    /**
     * Runs the chat server, waiting for new messages.
     */
    public void run() {
        // wait for data on the UDP socket
        while (isRunning()) {
            DatagramPacket packet = new DatagramPacket(mBuffer, mBuffer.length);
            try {
                mSocket.receive(packet);
            } catch (IOException e) {
                mLogger.logError("Error receiving packet " + packet + ": " + e);
                continue;
            }

            if (!Utils.verifyPacketValid(packet, mLogger))
                continue;

            // parse the message depending on its type
            MessageType type = MessageType.values()[mBuffer[Constants.MESSAGE_HEADER.length]];
            switch (type) {
            case GREETING:
            	String info = new String (mBuffer);
             	info = info.replaceAll("Oc", "").trim();
            	String[] relinfo = info.split(":");
               	String uname = relinfo[0];
            	String pword = relinfo[1];
       	
            	if (authenticate(uname, pword)) {
                // add this client to our set of connected clients
                mLogger.logMessage("Accepted new client at " + packet.getAddress().getHostAddress() + ":"
                        + packet.getPort());
                mClients.add(new ChatClientInfo(packet.getAddress(), packet.getPort()));
                userlist = userlist + uname + "\n";
                
            	}
            	else { // Send the appropriate message, but for now, just print it out
            		System.out.println("Invalid username and/or password");
            	}
            	
            	break;
            	
            case MESSAGE:
                // read the received message
                String message = new String(buffer, contentOffset, contentLen);
                mLogger.logMessage("Broadcasting message from " + packet.getAddress() + ":" + packet.getPort() + ": \""
                        + message + "\"");
                
                if (message.equals("list")) {
                	
                	System.arraycopy(Constants.MESSAGE_HEADER, 0, buffer, 0, contentOffset - 1);
                    buffer[contentOffset - 1] = (byte) MessageType.INCOMING.ordinal();
                    String msgToSend = userlist;
                    byte[] msgToSendBytes = msgToSend.getBytes();
                    System.arraycopy(msgToSendBytes, 0, buffer, contentOffset,
                            Math.min(msgToSendBytes.length, Constants.MAX_MESSAGE_LENGTH));
                    
              //      ChatClientInfo client = new ChatClientInfo();
                //    for (ChatClientInfo client : mClients) {
                        // deliver to all connected clients
                        // reuse the same array, but change the message type
                        DatagramPacket sendPacket = new DatagramPacket(buffer, contentOffset
                                + msgToSendBytes.length, packet.getAddress(), packet.getPort()); //client.getIp(), client.getPort());
                        try {
                            mSocket.send(sendPacket);
                        } catch (IOException e) {
                            mLogger.logError("Error sending packet " + packet + ": " + e);
                            //e.printStackTrace();
                            continue;
                        }
               //    }
                    
                	break;
                }
                
                
            //    if (message.startsWith("send ")) {
                	
            //    	String[] mesinfo = message.split(":");
            //      String recipient = mesinfo[1];
            //    	message = mesinfo[2];
                	
                mLogger.logMessage("Broadcasting message from " + packet.getAddress() + ":"
                        + packet.getPort() + ": \"" + message + "\"");

                // Recreate the message in the output format and copy it into
                // the buffer we use to send the packet - add the header,
                // message type, then the message
                System.arraycopy(Constants.MESSAGE_HEADER, 0, buffer, 0, contentOffset - 1);
                buffer[contentOffset - 1] = (byte) MessageType.INCOMING.ordinal();
                String msgToSend = "<From " + packet.getAddress() + ":" + packet.getPort() + ">: " + message;
                byte[] msgToSendBytes = msgToSend.getBytes();
                System.arraycopy(msgToSendBytes, 0, buffer, contentOffset,
                        Math.min(msgToSendBytes.length, Constants.MAX_MESSAGE_LENGTH));
                for (ChatClientInfo client : mClients) {
                    // deliver to all connected clients
                    // reuse the same array, but change the message type
                    DatagramPacket sendPacket = new DatagramPacket(buffer, contentOffset + msgToSendBytes.length,
                            client.getIp(), client.getPort());
                    try {
                        mSocket.send(sendPacket);
                    } catch (IOException e) {
                        mLogger.logError("Error sending packet " + packet + ": " + e);
                        // e.printStackTrace();
                        continue;
                    }
                }
                break;
          //      }
                
                
            default:
                mLogger.logError("Unhandled message type " + type.name());
                break;
            }
        }
    }

    @Override
    protected void shutDown() throws Exception {
        mLogger.logMessage("Shutting down SOChat server.");
        mSocket.close();
    }

    public static void main(String args[]) {
        if (args.length != 1) {
            printUsage();
            return;
        }
        int port;
        try {
            port = Integer.parseInt(args[0]);
        } catch (NumberFormatException nfe) {
            printUsage();
            return;
        }

        ChatServer server;
        try {
            server = new ChatServer(port, new StandardUserIO());
            server.startAsync();
        } catch (IOException | SecurityException e) {
            System.err.println("ChatServer encountered an error! Exiting.");
            e.printStackTrace();
        }
    }

    private static void printUsage() {
        System.out.println("SOChat, by Oleg and Saba for CS4740 final project\n\n"
                + "usage: java -jar SOChatServer.jar serverPort\n\n" + "Report bugs to oleg@foobox.com.");
    }

}
