package com.sochat.server;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import com.google.common.util.concurrent.AbstractExecutionThreadService;
import com.sochat.server.db.ServerUserDatabase;
import com.sochat.shared.Constants;
import com.sochat.shared.Constants.MessageType;
import com.sochat.shared.CryptoUtils;
import com.sochat.shared.SoChatException;
import com.sochat.shared.Utils;
import com.sochat.shared.io.StandardUserIO;
import com.sochat.shared.io.UserIO;

/**
 * Class that contains the chat server, which is responsible for containing the list of credentials for valid users.
 * 
 * Note that for the specifications of this project, this server keeps its "database" in memory. If the server is
 * restarted then its state will be lost.
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
     * The logger this server will use to print messages (or save somewhere for unit tests).
     */
    private final UserIO mLogger;

    /**
     * Cryptographic utiuls.
     */
    private final CryptoUtils mCrypto;

    /**
     * Our user database.
     */
    private final ServerUserDatabase mDb = new ServerUserDatabase();

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
    public ChatServer(int port, UserIO logger, String privateKeyModulus, String privateKeyExponent) throws IOException,
            GeneralSecurityException {
        mPrivateKey = ServerPrivateKey.getServerPrivateKey(privateKeyModulus, privateKeyExponent);
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
                mLogger.logError("Error processing message: " + e.getMessage());
                // e.printStackTrace();
                continue;
            }
        }

    }

    /**
     * Handle a received packet.
     * 
     * @param packet
     * @throws IOException
     * @throws SoChatException
     * @throws GeneralSecurityException
     */
    private void processPacket(DatagramPacket packet) throws IOException, GeneralSecurityException, SoChatException {
        // parse the message depending on its type
        MessageType type = MessageType.fromId(mBuffer[Constants.MESSAGE_HEADER.length]);
        switch (type) {
        case CS_AUTH1: {
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

            // if user is already authenticated, don't kick the valid user out -
            // return
            if (mDb.isUserAuthenticated(username))
                throw new SoChatException("User " + username + " is already logged in.");

            if (mDb.getUserN(username) <= 1)
                throw new SoChatException("Authentication expired. Please see administrator to renew password.");

            mDb.addUserAddress(username, packet.getSocketAddress());
            mDb.setUserC1sym(username, c1sym);

            String salt = DatatypeConverter.printBase64Binary(mDb.getUserSalt(username));
            int n = mDb.getUserN(username);
            String auth2 = r.toString(16) + "::" + salt + "::" + n;
            byte[] auth2encrypted = mCrypto.encryptWithSharedKey(c1sym, auth2);

            // send response!
            Utils.sendUdpMessage(mSocket, packet.getSocketAddress(), mBuffer, MessageType.CS_AUTH2, auth2encrypted);

            break;
        }
        case CS_AUTH3: {
            String username9 = mDb.getUsernameByAddress(packet.getSocketAddress());
            if (!mDb.existsUser(username9))
                throw new SoChatException("Invalid username (9) " + username9);
            SecretKey c1sym_9 = mDb.getUserServerSharedKey(username9);

            byte[] encrypted9 = Arrays.copyOfRange(mBuffer, Constants.MESSAGE_HEADER.length + 1, packet.getLength());
            String hashNminusOne = mCrypto.decryptWithSharedKey(c1sym_9, encrypted9);

            // try to take hash(hash^n-1) and see if it matches the expected
            // password
            String hashOfHashNminusOne = mCrypto.calculateLamportHash(hashNminusOne, mDb.getUserSalt(username9), 1);
            String currentHash = mDb.getUserPasswordHash(username9);
            mLogger.logDebug("hashOfHashNminusOne: " + hashOfHashNminusOne + "; currentHash: " + currentHash
                    + "; hashNminusOne: " + hashNminusOne);

            String response;

            // check that authentication is successful
            if (!currentHash.equals(hashOfHashNminusOne)) {
                response = Constants.AUTH_FAIL;
                // TODO: for repeated bad password/online attacks, block user
                mDb.clearUserAddressIfExists(username9);
                mLogger.logMessage("*** Invalid login from user " + username9 + " (" + packet.getSocketAddress() + ").");
            } else {
                mLogger.logMessage("New client connected: " + username9 + " (" + packet.getSocketAddress() + ").");
                mDb.setUserAuthenticated(username9, true);
                response = Constants.AUTH_SUCCESS;
            }
            byte[] responseBytes9 = mCrypto.encryptWithSharedKey(c1sym_9, response);

            // send response!
            Utils.sendUdpMessage(mSocket, packet.getSocketAddress(), mBuffer, MessageType.CS_AUTH4, responseBytes9);

            break;
        }
        case CMD_LIST: {
            String username1 = mDb.getUsernameByAddress(packet.getSocketAddress());
            mLogger.logDebug("Received list command from " + packet.getSocketAddress() + "(" + username1 + ")");

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

            // send response!
            Utils.sendUdpMessage(mSocket, packet.getSocketAddress(), mBuffer, MessageType.CMD_LIST_RESPONSE,
                    listInfoEncrypted);

            break;
        }
        case CC_AUTH3: {
            String username3 = mDb.getUsernameByAddress(packet.getSocketAddress());
            mLogger.logMessage("Received client-to-client auth msg #3 from " + packet.getSocketAddress() + "("
                    + username3 + ")");

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
                throw new SoChatException(
                        "Recipient's username does not match intended recipient. An attack may be underway!");
            }
            BigInteger nc2 = new BigInteger(C2SymDataSplit[1], 16);

            // Now construct the response packet
            // C1Sym{NC1, K12, Username(C2), C2Sym{K12, Username(C1), NC2}}

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

            // send response!
            Utils.sendUdpMessage(mSocket, packet.getSocketAddress(), mBuffer, MessageType.CC_AUTH4, response3Encrypted);

            break;
        }
        default:
            mLogger.logError("Received unhandled/unknown packet of type " + type);
            break;

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

        // read in modulus and exponent from file
        String privateKeyModulus, privateKeyExponent;
        try {
            BufferedReader reader = new BufferedReader(new FileReader("server.config"));
            privateKeyModulus = reader.readLine().trim();
            privateKeyExponent = reader.readLine().trim();
            reader.close();

            // basic validation
            if (!privateKeyModulus.startsWith("private_key_modulus=")
                    || !privateKeyExponent.startsWith("private_key_exponent="))
                throw new SoChatException("error reading fields");

            privateKeyModulus = privateKeyModulus.replaceFirst("private_key_modulus=", "");
            privateKeyExponent = privateKeyExponent.replaceFirst("private_key_exponent=", "");
        } catch (IOException | SoChatException e) {
            System.err.println("Error while reading in server configuration: " + e.getMessage()
                    + " - please see README.md.");
            return;
        }

        ChatServer server;
        try {
            server = new ChatServer(port, new StandardUserIO(), privateKeyModulus, privateKeyExponent);
            server.startAsync();
        } catch (IOException | SecurityException | GeneralSecurityException e) {
            System.err.println("ChatServer encountered an error. Exiting. Details: " + e.getLocalizedMessage());
            // e.printStackTrace();
        }
    }

    private static void printUsage() {
        System.out.println("SOChat, by Oleg and Saba for a final project\n\n"
                + "usage: java -jar SOChatServer.jar serverPort\n\n" + "Report bugs to oleg@foobox.com.");
    }
}
