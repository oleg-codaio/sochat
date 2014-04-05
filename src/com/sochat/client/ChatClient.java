package com.sochat.client;

import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.lang3.tuple.Pair;

import com.sochat.shared.Constants;
import com.sochat.shared.Constants.MessageType;
import com.sochat.shared.CryptoUtils;
import com.sochat.shared.Utils;
import com.sochat.shared.io.StandardUserIO;
import com.sochat.shared.io.UserIO;
import com.sun.xml.internal.messaging.saaj.util.Base64;

/**
 * Class that contains the chat client, which can send the GREETING message to
 * establish a connection to a chat server as well as send the chat server a
 * message to be sent to other chat servers.
 * 
 * @author Oleg, Saba
 */
public class ChatClient implements Runnable {

    private final PublicKey mServerKey;

    /**
     * The socket the client uses to listen for a particular port and dispatch
     * messages.
     */
    private final DatagramSocket mSocket;

    /**
     * The address on which the server is running.
     */
    private final InetSocketAddress mServerAddress;

    /**
     * Create a buffer that will be used for sending/receiving UDP packets.
     */
    private final byte[] mBuffer = new byte[Constants.MAX_MESSAGE_LENGTH];

    /**
     * The logger this server will use to print messages.
     */
    private final UserIO mUserIo;

    private final ClientInputReader mInput;

    /**
     * Contains various cryptographic utilities.
     */
    private final CryptoUtils mCrypto = new CryptoUtils();

    /**
     * Creates a new chat client running on the specified port.
     * 
     * @param port
     * @throws IOException
     *             Thrown if there was an issue connecting to the socket.
     * @throws GeneralSecurityException
     */
    public ChatClient(InetAddress serverAddress, int serverPort, UserIO logger) throws IOException,
            GeneralSecurityException {
        mUserIo = logger;
        mInput = new ClientInputReader(mUserIo);
        mServerKey = ServerPublicKey.getServerPublicKey();

        mUserIo.logMessage("Starting ChatClient...");
        mServerAddress = new InetSocketAddress(serverAddress, serverPort);
        mSocket = new DatagramSocket(); // bind to wildcard port
        mUserIo.logMessage("Listening on port " + mSocket.getLocalPort() + "...");
    }

    /**
     * Runs the chat client, spawning child worker thread for each connection
     * and processing new messages.
     */
    public void run() {
        // start listener thread
        new ProcessReceivedMessagesThread().start();

        // start of authentication protocol
        try {
            Pair<String, String> credentials = mInput.readCredentials();
            if (credentials == null) {
                return;
            }

            initAuth(credentials.getLeft(), credentials.getRight());
        } catch (IOException e1) {
            e1.printStackTrace();
        }

        mUserIo.logMessage("Client initialized! Type a message and press enter to send it to the server.");

        // wait for user to enter text, then send it to the server
        while (true) {
            // create a new MESSAGE message with the user's text
            // mLogger.logMessage("> "); // don't use this for now
            try {
                String line = mUserIo.readLineBlocking().trim();
            } catch (IOException e) {
                mUserIo.logError("Error sending MESSAGE to server: " + e);
                // e.printStackTrace();
                continue;
            }
        }
    }

    private void initAuth(String username, String password) throws IOException {
        // generate our symmetric key and random number
        SecretKey key = mCrypto.generateSecretKey();
        String keyBase64 = DatatypeConverter.printBase64Binary(key.getEncoded());
        BigInteger r = mCrypto.generateRandom();
        String rStr = r.toString(16);

        // concatenate message
        StringBuilder b = new StringBuilder();
        b.append(username);
        b.append("::");
        b.append(rStr);
        b.append("::");
        b.append(keyBase64);
        String info = b.toString();

        mUserIo.logDebug("message1 = " + info);

        // encrypt with server public key
        byte[] encrypted = mCrypto.encryptData(info, mServerKey);

        // create header
        byte[] messageHeader = Utils.getHeaderForMessageType(MessageType.CS_AUTH1);

        // copy header and encrypted message into our buffer
        System.arraycopy(messageHeader, 0, mBuffer, 0, messageHeader.length);
        // copy the encrypted message
        System.arraycopy(encrypted, 0, mBuffer, messageHeader.length, encrypted.length);

        int len = messageHeader.length + encrypted.length;
        
        mUserIo.logDebug("Sent length is: " + len);

        // send!
        sendCurrentBufferAsPacket(len);
    }

    public boolean sendCurrentBufferAsPacket(int length) {
        try {
            DatagramPacket attachPacket = new DatagramPacket(mBuffer, length, mServerAddress);
            mSocket.send(attachPacket);
            mUserIo.logDebug("sending packet: " + new String(DatatypeConverter.printBase64Binary(mBuffer)));
            return true;
        } catch (IOException e) {
            mUserIo.logError("Error sending packet: " + e);
            return false;
        }
    }

    public int getPort() {
        return mSocket.getLocalPort();
    }

    public void stop() {
        mSocket.close();
    }

    /**
     * Thread that asynchronously receives messages from the socket and prints
     * them on the screen.
     */
    private class ProcessReceivedMessagesThread extends Thread {

        @Override
        public void run() {
            while (true) {
                DatagramPacket packet = new DatagramPacket(mBuffer, mBuffer.length);
                try {
                    mSocket.receive(packet);
                } catch (IOException e) {
                    mUserIo.logError("Error receiving packet " + packet + ": " + e);
                    // e.printStackTrace();
                    continue;
                }

                int len = packet.getLength();
                byte[] buffer = packet.getData();

                int contentOffset = Constants.MESSAGE_HEADER.length + 1;
                int contentLen = packet.getLength() - contentOffset;

                // check that the length seems valid (header + message type
                // byte)
                if (len < Constants.MESSAGE_HEADER.length + 1) {
                    mUserIo.logMessage("Invalid message received.");
                    continue;
                }

                // check that version matches
                if (!Utils.arrayEquals(Constants.MESSAGE_HEADER, 0, buffer, 0, Constants.MESSAGE_HEADER.length)) {
                    mUserIo.logMessage("Packet received is not a Chat packet or is from an old version.");
                    continue;
                }

                // the next byte contains the message type
                byte messageType = buffer[contentOffset - 1];
                if (messageType < 0 || messageType >= MessageType.values().length) {
                    mUserIo.logMessage("Invalid message type " + messageType);
                    continue;
                }

                // parse the message depending on its type
                MessageType type = MessageType.values()[messageType];
                switch (type) {
                case CS_AUTH2:
                    // print the incoming message
                    String msg = new String(packet.getData(), contentOffset, contentLen);
                    mUserIo.logMessage(msg);
                    break;

                default:
                    mUserIo.logMessage("Unhandled message type " + type.name());
                    break;
                }
            }
        }
    }

    public static void main(String args[]) {
        if (args.length != 2) {
            printUsage();
            return;
        }
        InetAddress serverAddress;
        try {
            serverAddress = InetAddress.getByName(args[0]);
        } catch (UnknownHostException e) {
            e.printStackTrace();
            printUsage();
            return;
        }
        int serverPort;
        try {
            serverPort = Integer.parseInt(args[1]);
        } catch (NumberFormatException nfe) {
            printUsage();
            return;
        }

        ChatClient client;
        try {
            client = new ChatClient(serverAddress, serverPort, new StandardUserIO());
            client.run();
        } catch (IOException | SecurityException | GeneralSecurityException e) {
            System.err.println("ChatClient encountered an error! Exiting.");
            e.printStackTrace();
        }
    }

    private static void printUsage() {
        System.out.println("SOChat, by Oleg and Saba for CS4740 final project\n\n"
                + "usage: java SOChat serverIpAddress serverPort\n\n" + "Report bugs to me@olegvaskevich.com.");
    }

}
