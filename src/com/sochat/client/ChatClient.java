package com.sochat.client;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.lang3.tuple.Pair;

import com.sochat.client.db.ClientUserCache;
import com.sochat.shared.Constants;
import com.sochat.shared.Constants.MessageType;
import com.sochat.shared.CryptoUtils;
import com.sochat.shared.SoChatException;
import com.sochat.shared.Utils;
import com.sochat.shared.io.StandardUserIO;
import com.sochat.shared.io.UserIO;

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
     * Cache containing available users.
     */
    private final ClientUserCache mUsers = new ClientUserCache();

    /**
     * Create a buffer that will be used for sending/receiving UDP packets on
     * main thread.
     */
    private final byte[] mBuffer = new byte[Constants.MAX_MESSAGE_LENGTH];

    /**
     * The logger this server will use to print messages.
     */
    private final UserIO mUserIo;

    /**
     * This client's username.
     */
    private String mUsername;

    /**
     * Read input from user.
     */
    private final ClientInputReader mInput;

    /**
     * Contains various cryptographic utilities.
     */
    private final CryptoUtils mCrypto = new CryptoUtils();

    /**
     * Last shared C1Sym key (null at first until we generate it when
     * authenticating with the server).
     */
    private SecretKey mC1Sym;

    /**
     * Whether we are fully connected to server.
     */
    private boolean mConnected = false;

    /**
     * The 'R' that is used to make sure the list response is valid.
     */
    private BigInteger mLastListCommandR;

    /**
     * Creates a new chat client running on the specified port.
     * 
     * @param port
     * @throws IOException
     *             Thrown if there was an issue connecting to the socket.
     * @throws GeneralSecurityException
     */
    public ChatClient(InetAddress serverAddress, int serverPort, UserIO logger) throws IOException, GeneralSecurityException {
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
        } catch (IOException | GeneralSecurityException e1) {
            mUserIo.logError("Error logging in to server: " + e1.toString());
            e1.printStackTrace();
            return;
        }

        mUserIo.logMessage("Client initialized! Type a message and press enter to send it to the server.");
        mConnected = true;

        while (!mConnected) {
            // do nothing, wait for server connection
        }

        // wait for user to enter text, then send it to the server
        while (true) {
            try {
                String input;
                try {
                    input = mUserIo.readLineBlocking().trim();
                } catch (IOException e) {
                    mUserIo.logError("Error sending MESSAGE to server: " + e);
                    continue;
                }

                if (input == null) {
                    mUserIo.logMessage("Empty command");
                } else if ("list".equals(input)) {
                    sendListCommand();
                } else if ("send".equals(input.trim().split(" ")[0])) {
                    // send USERNAME MESSAGE
                    String[] msg = Utils.getMessageSplit(input);
                    if (msg == null) {
                        mUserIo.logMessage("Bad send command");
                        continue;
                    }
                    String username = msg[1], message = msg[2];
                    sendMessage(username, message);
                } else {
                    mUserIo.logMessage("Unknown command " + input);
                }

            } catch (GeneralSecurityException | SoChatException e) {
                mUserIo.logError("Error: " + e);
            }

        }
    }

    private void initAuth(String username, String password) throws IOException, GeneralSecurityException, IllegalBlockSizeException,
            BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        mUsername = username;

        // generate our symmetric key and random number
        mC1Sym = mCrypto.generateSecretKey();
        String keyBase64 = DatatypeConverter.printBase64Binary(mC1Sym.getEncoded());
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

        // compute length
        int len = messageHeader.length + encrypted.length;

        // send!
        sendCurrentBufferAsPacketToServer(len);
    }

    private void sendMessage(String username, String message) throws SoChatException {
        // TODO
        if (!mUsers.existsUser(username)) {
            System.out.println("No such user!");
        } else if (mUsers.isUserAuthenticated(username)) {
            // Encrypt message with K12 and send it out
        } else { // Connected, but not authenticated

            // FIRST MESSAGE OF THE PROTOCOL
            // //////////////////////////////////////////////////////////////////////////////////////////

            SocketAddress c2address = mUsers.getAddress(username);
            Arrays.fill(mBuffer, (byte) 0);
            // create header
            byte[] messageHeader = Utils.getHeaderForMessageType(MessageType.CC_AUTH1);

            // copy header and encrypted message into our buffer
            System.arraycopy(messageHeader, 0, mBuffer, 0, messageHeader.length);

            // copy the encrypted message
            System.arraycopy(mUsername.getBytes(), 0, mBuffer, messageHeader.length, mUsername.getBytes().length);

            // compute length
            int len = messageHeader.length + mUsername.getBytes().length;

            // send!
            sendCurrentBufferAsPacket(len, c2address);

            // //////////////////////////////////////////////////////////////////////////////////////////////
        }
    }

    private void sendListCommand() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException, GeneralSecurityException {
        // send LIST request to server
        Arrays.fill(mBuffer, (byte) 0);

        // create header
        byte[] messageHeader = Utils.getHeaderForMessageType(MessageType.CMD_LIST);
        System.arraycopy(messageHeader, 0, mBuffer, 0, messageHeader.length);

        mLastListCommandR = mCrypto.generateRandom();
        String rStr = mLastListCommandR.toString(16);
        mUserIo.logDebug("mLastListCommandR = " + rStr);
        byte[] encrypted = mCrypto.encryptWithSharedKey(mC1Sym, rStr);
        System.arraycopy(encrypted, 0, mBuffer, messageHeader.length, encrypted.length);

        // compute length
        int len = messageHeader.length + encrypted.length;

        // send!
        sendCurrentBufferAsPacketToServer(len);

        mUserIo.logDebug("Client sent list request: " + rStr);
    }

    public boolean sendCurrentBufferAsPacketToServer(int length) {
        return sendCurrentBufferAsPacket(length, mServerAddress);
    }

    public boolean sendCurrentBufferAsPacket(int length, SocketAddress address) {
        try {
            DatagramPacket attachPacket = new DatagramPacket(mBuffer, length, address);
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
        /**
         * Create a buffer that will be used for sending/receiving UDP packets
         * on receive thread.
         */
        private final byte[] mReceiveBuffer = new byte[Constants.MAX_MESSAGE_LENGTH];

        @Override
        public void run() {
            while (true) {
                Arrays.fill(mReceiveBuffer, (byte) 0);
                DatagramPacket packet = new DatagramPacket(mReceiveBuffer, mReceiveBuffer.length);
                try {
                    mSocket.receive(packet);
                } catch (IOException e) {
                    mUserIo.logError("Error receiving packet: " + e.toString());
                    // e.printStackTrace();
                    continue;
                }

                // check that the packet is good
                if (!Utils.verifyPacketValid(packet, mUserIo))
                    continue;

                mUserIo.logDebug("received data (receive thread): " + DatatypeConverter.printBase64Binary(mReceiveBuffer));

                // parse the message depending on its type
                try {
                    processReceivedPacket(packet);
                } catch (GeneralSecurityException | SoChatException | UnsupportedEncodingException e) {
                    mUserIo.logError("Error processing packet: " + e.toString());
                    e.printStackTrace();
                }
            }
        }

        private void processReceivedPacket(DatagramPacket packet) throws GeneralSecurityException, SoChatException, UnsupportedEncodingException {
            MessageType type = MessageType.fromId(mReceiveBuffer[Constants.MESSAGE_HEADER.length]);
            switch (type) {
            case CS_AUTH2:
                break;
            case CS_AUTH4:
                break;
            case CC_AUTH1:
                byte[] ccauth1 = Arrays.copyOfRange(mReceiveBuffer, Constants.MESSAGE_HEADER.length + 1, packet.getLength());
                String c1username = new String(ccauth1, "UTF-8");
                System.out.println(c1username);
                break;
            case CMD_LIST_RESPONSE:
                byte[] encrypted = Arrays.copyOfRange(mReceiveBuffer, Constants.MESSAGE_HEADER.length + 1, packet.getLength());

                // decrypt data
                String decrypted = mCrypto.decryptWithSharedKey(mC1Sym, encrypted);
                mUserIo.logDebug("Received list response from server: " + decrypted);

                String[] info = decrypted.split("::");
                BigInteger r = new BigInteger(info[0], 16);
                String list = info[1];

                // check that R matches
                if ((r.equals(mLastListCommandR)) == false) {
                    System.out.println("r = " + r);
                    System.out.println("mLastListCommandR = " + mLastListCommandR);
                    r = null;
                    throw new SoChatException("Stray list response received!");
                } else {
                    mUserIo.logMessage("Online users:\n" + list);
                    mUsers.updateList(list);
                    r = null;
                }

                break;

            default:
                mUserIo.logMessage("Unhandled message type " + type.name());
                break;
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
        System.out.println("SOChat, by Oleg and Saba for CS4740 final project\n\n" + "usage: java SOChat serverIpAddress serverPort\n\n"
                + "Report bugs to me@olegvaskevich.com.");
    }

}
