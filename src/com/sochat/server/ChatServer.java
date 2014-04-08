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
import com.sochat.server.db.ServerUserCache;
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
    private final ServerUserCache mDb = new ServerUserCache();

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
            // mLogger.logDebug("received data: " +
            // DatatypeConverter.printBase64Binary(mBuffer));

            try {
                processPacket(packet);
            } catch (IOException | SoChatException | GeneralSecurityException e) {
                mLogger.logError("Error processing message: " + e.toString());
                e.printStackTrace();
                continue;
            }
        }

    }

    private void processPacket(DatagramPacket packet) throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            NoSuchAlgorithmException, NoSuchPaddingException, SoChatException, GeneralSecurityException {
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

            // mLogger.logDebug("Username: " + username);
            // mLogger.logDebug("R = " + r);
            // mLogger.logDebug("C1sym = " + c1sym);

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

            SecretKey c1sym1 = mDb.getUserServerSharedKey(username1);

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

            // mLogger.logDebug("List command response: " + listInfo);

            // send it!
            int len = messageHeader.length + listInfoEncrypted.length;
            sendBufferAsPacket(packet.getSocketAddress(), len);

            break;
        case CC_AUTH3:
            String username3 = mDb.getUsernameByAddress(packet.getSocketAddress());
            mLogger.logMessage("Received client-to-client auth msg #3 from " + packet.getSocketAddress() + "(" + username3 + ")");

            // check to make sure the clients are authenticated
            if (!mDb.isUserAuthenticated(username3)) {
                mLogger.logError("Received auth command from inactive/no username " + username3);
                return;
            }

            // decrypt - redundant, but this way an exception will be thrown if
            // the number is not a BigInteger
            byte[] data3 = Arrays.copyOfRange(mBuffer, Constants.MESSAGE_HEADER.length + 1, packet.getLength());
            String data3Str = new String(data3, "UTF-8");
            mLogger.logDebug("Received auth3 packet: " + data3Str);
            String[] data3Split = data3Str.split("::");
            if (data3Split.length != 4) {
                // TODO: send error message back?
                throw new SoChatException("CC auth msg #3 is malformed.");
            }
            String usernameC1 = data3Split[0];
            String usernameC2 = data3Split[1];
            if (!usernameC1.equals(username3)) {
                // TODO: send error message back?
                throw new SoChatException("IP address does not match username. An attack may be underway!");
            }
            if (!mDb.existsUser(usernameC2)) {
                // TODO: send error message back?
                throw new SoChatException("Receipient username does not exist!");
            }
            BigInteger nc1 = new BigInteger(data3Split[2], 16);
            byte[] encryptedC2SymData = DatatypeConverter.parseBase64Binary(data3Split[3]);
            SecretKey c2sym = mDb.getUserServerSharedKey(usernameC2);
            String C2SymData = mCrypto.decryptWithSharedKey(c2sym, encryptedC2SymData);
            String[] C2SymDataSplit = C2SymData.split("::");
            if (C2SymDataSplit.length != 2) {
                // TODO: send error message back?
                throw new SoChatException("CC auth msg #3 is malformed (2).");
            }
            mLogger.logDebug("C2SymData: " + C2SymData + "; " + C2SymDataSplit[0] + "; " + C2SymDataSplit[1]);
            String usernameC1_C2 = C2SymDataSplit[0];
            if (!usernameC1_C2.equals(username3)) {
                // TODO: send error message back?
                throw new SoChatException("Recipient's username does not match intended recipient. An attack may be underway!");
            }
            BigInteger nc2 = new BigInteger(C2SymDataSplit[1], 16);

            // Now construct the response packet
            // C1Sym{NC1, K12, Username(C2), C2Sym{K12, Username(C1), N’C2}}

            // session key for data, should be forgotten by server for sake of
            // forward secrecy
            String k12 = DatatypeConverter.printBase64Binary(mCrypto.generateSecretKey().getEncoded());
            StringBuilder C2SymDataReturn = new StringBuilder();
            C2SymDataReturn.append(k12);
            C2SymDataReturn.append("::");
            C2SymDataReturn.append(usernameC1);
            C2SymDataReturn.append("::");
            C2SymDataReturn.append(nc2.toString(16));
            String C2SymDataReturnStr = C2SymDataReturn.toString();
            byte[] C2SymDataReturn_encrypted = mCrypto.encryptWithSharedKey(c2sym, C2SymDataReturnStr);
            String C2SymDataReturn_encryptedStr = DatatypeConverter.printBase64Binary(C2SymDataReturn_encrypted);
            // mUserIo.logDebug("Encrypting C2Sym '" +
            // DatatypeConverter.printBase64Binary(mC1Sym.getEncoded()) + "': "
            // + DatatypeConverter.printBase64Binary(ccauth5));

            StringBuilder responseBuilder3 = new StringBuilder();
            responseBuilder3.append(nc1.toString(16));
            responseBuilder3.append("::");
            responseBuilder3.append(k12);
            responseBuilder3.append("::");
            responseBuilder3.append(usernameC2);
            responseBuilder3.append("::");
            responseBuilder3.append(C2SymDataReturn_encryptedStr);

            SecretKey c1sym_3 = mDb.getUserServerSharedKey(usernameC1);
            String response3 = responseBuilder3.toString();
            mLogger.logDebug("Sending out auth msg #4: " + response3);
            byte[] response3Encrypted = mCrypto.encryptWithSharedKey(c1sym_3, response3);

            // create buffer with header and list info
            Arrays.fill(mBuffer, (byte) 0);
            byte[] messageHeader3 = Utils.getHeaderForMessageType(MessageType.CC_AUTH4);
            System.arraycopy(messageHeader3, 0, mBuffer, 0, messageHeader3.length);
            System.arraycopy(response3Encrypted, 0, mBuffer, messageHeader3.length, response3Encrypted.length);

            // send it!
            int len3 = messageHeader3.length + response3Encrypted.length;
            sendBufferAsPacket(packet.getSocketAddress(), len3);
            break;
        default:
            mLogger.logError("Received unhandled/unknown packet of type " + type);
            break;

        }
    }

    public boolean sendBufferAsPacket(SocketAddress address, int length) {
        try {
            DatagramPacket packet = new DatagramPacket(mBuffer, length, address);
            mSocket.send(packet);
            // mLogger.logDebug("sending packet: " + new
            // String(DatatypeConverter.printBase64Binary(mBuffer)));
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
        System.out.println("SOChat, by Oleg and Saba for CS4740 final project\n\n" + "usage: java -jar SOChatServer.jar serverPort\n\n"
                + "Report bugs to oleg@foobox.com.");
    }
}