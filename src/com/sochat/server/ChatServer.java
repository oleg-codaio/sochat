package com.sochat.server;

import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import com.google.common.util.concurrent.AbstractExecutionThreadService;
import com.sochat.server.db.UserDatabase;
import com.sochat.shared.Constants;
import com.sochat.shared.Constants.MessageType;
import com.sochat.shared.CryptoUtils;
import com.sochat.shared.SoChatException;
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
     * Cryptographic utiuls.
     */
    private final CryptoUtils mCrypto;

    /**
     * Our user database.
     */
    private final UserDatabase mDb = new UserDatabase();

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
        mCrypto = new CryptoUtils();
        mPort = port;
        mSocket = new DatagramSocket(mPort);
    }

    @Override
    protected void startUp() throws Exception {
        mLogger.logMessage("Starting SOChat Server...");
        mLogger.logMessage("Running on " + mSocket.getLocalAddress() + ":" + mSocket.getLocalPort() + "...");
        mLogger.logMessage("Server initialized...");
    }

    static String beforespace(String str) {
        int count = 0;
        String result = "";
        for (int x = 0; x < str.length() - 5; x++) {
            if (str.charAt(x) == ' ')
                break;
            else {
                count = count + 1;
                result = result.concat(str.substring(x, x + 1));
            }
        }
        return result;
    }

    /**
     * Runs the chat server, waiting for new messages.
     * 
     * @throws IOException
     */
    public void run() {
        // wait for data on the UDP socket
        while (isRunning()) {
            Arrays.fill(mBuffer, (byte) 0);
            DatagramPacket packet = new DatagramPacket(mBuffer, mBuffer.length);
            try {
                mSocket.receive(packet);
            } catch (IOException e) {
                mLogger.logError("Error receiving packet " + packet + ": " + e);
                continue;
            }

            if (!Utils.verifyPacketValid(packet, mLogger))
                continue;
            mLogger.logDebug("received data: " + DatatypeConverter.printBase64Binary(mBuffer));

            try {
                processPacket(packet);
            } catch (IOException | SoChatException | GeneralSecurityException e) {
                mLogger.logError("Error processing message: " + e.toString());
                e.printStackTrace();
                continue;
            }
        }
        /*
         * switch (type) { case GREETING: String info = new String(mBuffer);
         * info = info.replaceAll("Oc", "").trim(); String[] relinfo =
         * info.split(":"); String uname = relinfo[0]; String pword =
         * relinfo[1];
         * 
         * if (authenticate(uname, pword)) { // add this client to our set of
         * connected clients mLogger.logMessage("Accepted new client at " +
         * packet.getAddress().getHostAddress() + ":" + packet.getPort());
         * mClients.add(new ChatClientInfo(packet.getAddress(),
         * packet.getPort())); userlist = userlist + uname + "\n";
         * 
         * } else { // Send the appropriate message, but for now, just // print
         * it out System.out.println("Invalid username and/or password"); }
         * 
         * break;
         * 
         * case MESSAGE: // read the received message String message = new
         * String(buffer, contentOffset, contentLen);
         * mLogger.logMessage("Broadcasting message from " + packet.getAddress()
         * + ":" + packet.getPort() + ": \"" + message + "\"");
         * 
         * if (message.equals("list")) {
         * 
         * System.arraycopy(Constants.MESSAGE_HEADER, 0, buffer, 0,
         * contentOffset - 1); buffer[contentOffset - 1] = (byte)
         * MessageType.INCOMING.ordinal(); String msgToSend = userlist; byte[]
         * msgToSendBytes = msgToSend.getBytes();
         * System.arraycopy(msgToSendBytes, 0, buffer, contentOffset,
         * Math.min(msgToSendBytes.length, Constants.MAX_MESSAGE_LENGTH));
         * 
         * // ChatClientInfo client = new ChatClientInfo(); // for
         * (ChatClientInfo client : mClients) { // deliver to all connected
         * clients // reuse the same array, but change the message type
         * DatagramPacket sendPacket = new DatagramPacket(buffer, contentOffset
         * + msgToSendBytes.length, packet.getAddress(), packet.getPort()); //
         * client.getIp(), // client.getPort()); try { mSocket.send(sendPacket);
         * } catch (IOException e) { mLogger.logError("Error sending packet " +
         * packet + ": " + e); // e.printStackTrace(); continue; } // }
         * 
         * break; }
         * 
         * // if (message.startsWith("send ")) {
         * 
         * // String[] mesinfo = message.split(":"); // String recipient =
         * mesinfo[1]; // message = mesinfo[2];
         * 
         * mLogger.logMessage("Broadcasting message from " + packet.getAddress()
         * + ":" + packet.getPort() + ": \"" + message + "\"");
         */
        // Recreate the message in the output format and copy it into
        // the buffer we use to send the packet - add the header,
        // message type, then the message
        /*
         * System.arraycopy(Constants.MESSAGE_HEADER, 0, buffer, 0,
         * contentOffset - 1); buffer[contentOffset - 1] = (byte)
         * MessageType.INCOMING.ordinal(); String msgToSend = "<From " +
         * packet.getAddress() + ":" + packet.getPort() + ">: " + message;
         * byte[] msgToSendBytes = msgToSend.getBytes();
         * System.arraycopy(msgToSendBytes, 0, buffer, contentOffset,
         * Math.min(msgToSendBytes.length, Constants.MAX_MESSAGE_LENGTH)); for
         * (ChatClientInfo client : mClients) { // deliver to all connected
         * clients // reuse the same array, but change the message type
         * DatagramPacket sendPacket = new DatagramPacket(buffer, contentOffset
         * + msgToSendBytes.length, client.getIp(), client.getPort()); try {
         * mSocket.send(sendPacket); } catch (IOException e) {
         * mLogger.logError("Error sending packet " + packet + ": " + e); //
         * e.printStackTrace(); continue; } } break; // }
         * 
         * default: mLogger.logError("Unhandled message type " + type.name());
         * break; }
         */
    }

    private void processPacket(DatagramPacket packet) throws IOException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException,
            SoChatException, GeneralSecurityException {
        // parse the message depending on its type
        MessageType type = MessageType.fromId(mBuffer[Constants.MESSAGE_HEADER.length]);
        switch (type) {
        case CS_AUTH1:
            mLogger.logMessage("Initiated authentication request from " + packet.getSocketAddress());
            byte[] encrypted = Arrays.copyOfRange(mBuffer, Constants.MESSAGE_HEADER.length + 1, packet.getLength());

            // decrypt data
            String decrypted = mCrypto.decryptData(encrypted, mPrivateKey);

            String[] info = decrypted.split("::");
            String username = info[0];
            BigInteger r = new BigInteger(info[1], 16);
            byte[] c1symBytes = DatatypeConverter.parseBase64Binary(info[2]);
            SecretKey c1sym = new SecretKeySpec(c1symBytes, 0, c1symBytes.length, "AES");

            mLogger.logDebug("Username: " + username);
            mLogger.logDebug("R = " + r);
            mLogger.logDebug("C1sym = " + c1sym);

            // if user is not in our DB, abort
            // TODO: later, send error message back
            if (!mDb.existsUser(username))
                throw new SoChatException("Invalid username " + username);

            // check if user exists
            // TODO set to true
            mDb.addUserAddress(username, packet.getSocketAddress());
            mDb.setUserAuthenticated(username, true);
            mDb.setUserC1sym(username, c1sym);

            break;
        case CS_AUTH3:
            break;
        case CMD_LIST:
            String username1 = mDb.getUsernameByAddress(packet.getSocketAddress());
            mLogger.logMessage("Received list command from " + packet.getSocketAddress() + "(" + username1 + ")");

            // check to make sure the client has access to the LIST command
            if (!mDb.isUserAuthenticated(username1)) {
                mLogger.logError("Received list command from inactive/no username " + username1);
                return;
            }

            SecretKey c1sym1 = mDb.getUserC1sym(username1);

            // decrypt - redundant, but this way an exception will be thrown if
            // the number is not a BigInteger
            byte[] encrypted1 = Arrays.copyOfRange(mBuffer, Constants.MESSAGE_HEADER.length + 1, packet.getLength());
            String decrypted1 = mCrypto.decryptWithSharedKey(c1sym1, encrypted1);
            BigInteger r1 = new BigInteger(decrypted1, 16);

            // send a packet back containing the list and R
            String userList = mDb.getListOfConnectedUsers();
            String r1Str = r1.toString(16);
            StringBuilder listInfoBuilder = new StringBuilder();
            listInfoBuilder.append(r1Str);
            listInfoBuilder.append("::");
            listInfoBuilder.append(userList);
            String listInfo = listInfoBuilder.toString();
            byte[] listInfoEncrypted = mCrypto.encryptWithSharedKey(c1sym1, listInfo);

            // create buffer with header and list info
            Arrays.fill(mBuffer, (byte) 0);
            byte[] messageHeader = Utils.getHeaderForMessageType(MessageType.CMD_LIST_RESPONSE);
            System.arraycopy(messageHeader, 0, mBuffer, 0, messageHeader.length);
            System.arraycopy(listInfoEncrypted, 0, mBuffer, messageHeader.length, listInfoEncrypted.length);

            mLogger.logDebug("List command response: " + listInfo);
            mLogger.logDebug("List command response, encrypted: "
                    + DatatypeConverter.printBase64Binary(listInfoEncrypted));

            // send it!
            int len = messageHeader.length + listInfoEncrypted.length;
            sendBufferAsPacket(packet.getSocketAddress(), len);

            break;
        case CC_AUTH1:
            break;
        case CC_AUTH2:
            break;
        case CC_AUTH3:
            break;
        case CC_AUTH4:
            break;
        case CC_AUTH5:
            break;
        case CC_AUTH6:
            break;
        case CC_AUTH7:
            break;
        case UNKNOWN:
            break;
        default:
            break;

        }
    }

    public boolean sendBufferAsPacket(SocketAddress address, int length) {
        try {
            DatagramPacket packet = new DatagramPacket(mBuffer, length, address);
            mSocket.send(packet);
            mLogger.logDebug("sending packet: " + new String(DatatypeConverter.printBase64Binary(mBuffer)));
            return true;
        } catch (IOException e) {
            mLogger.logError("Error sending packet: " + e);
            return false;
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
        } catch (IOException | SecurityException | GeneralSecurityException e) {
            System.err.println("ChatServer encountered an error! Exiting.");
            e.printStackTrace();
        }
    }

    private static void printUsage() {
        System.out.println("SOChat, by Oleg and Saba for CS4740 final project\n\n"
                + "usage: java -jar SOChatServer.jar serverPort\n\n" + "Report bugs to oleg@foobox.com.");
    }

}
