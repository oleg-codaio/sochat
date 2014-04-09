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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.lang3.tuple.Pair;

import com.sochat.client.db.ClientUserCache;
import com.sochat.client.db.ClientUserInfo;
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
     * This client's username/password.
     */
    private Pair<String, String> mCredentials;

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
     * Used to await the connection.
     */
    private CountDownLatch mAwaitConnection = new CountDownLatch(1);

    /**
     * The 'R' used during authentication.
     */
    private BigInteger mRpriv;

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
            mCredentials = mInput.readCredentials();
            if (mCredentials == null) {
                return;
            }

            mUserIo.logMessage("Connecting...");
            initAuth();
        } catch (IOException | GeneralSecurityException e1) {
            mUserIo.logError("Error logging in to server: " + e1.toString());
            e1.printStackTrace();
            return;
        }

        try {
            // wait for connection to finish before we let the user interact
            // with the program
            if (!mAwaitConnection.await(5, TimeUnit.SECONDS))
                throw new InterruptedException();
        } catch (InterruptedException e2) {
            mUserIo.logError("Authentication timed out. Exiting.");
            System.exit(0);
        }

        try {
            sendListCommand();
        } catch (GeneralSecurityException e1) {
            // send list command at first
            mUserIo.logError("Could not send list command: " + e1.toString());
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

    private void initAuth() throws IOException, GeneralSecurityException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException,
            NoSuchPaddingException {
        // generate our symmetric key and random number
        mC1Sym = mCrypto.generateSecretKey();
        String keyBase64 = DatatypeConverter.printBase64Binary(mC1Sym.getEncoded());
        mRpriv = mCrypto.generateRandom();
        String rStr = mRpriv.toString(16);

        // concatenate message
        StringBuilder b = new StringBuilder();
        b.append(mCredentials.getLeft());
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

    private void sendMessage(String username, String message) throws SoChatException, GeneralSecurityException {
        if (!mUsers.existsUser(username)) {
            mUserIo.logMessage("No such user!");
        } else {
            ClientUserInfo user = mUsers.getUserInfo(username);

            if (user.isAuthenticated()) {
                // Encrypt message with K12 and send it out
                SocketAddress c2address = mUsers.getAddress(username);

                // send message
                byte[] encryptedMessage = mCrypto.encryptWithSharedKey(user.getK12(), message);
                Arrays.fill(mBuffer, (byte) 0);
                byte[] messageHeader = Utils.getHeaderForMessageType(MessageType.CC_MESSAGE);
                System.arraycopy(messageHeader, 0, mBuffer, 0, messageHeader.length);
                System.arraycopy(encryptedMessage, 0, mBuffer, messageHeader.length, encryptedMessage.length);
                int len = messageHeader.length + encryptedMessage.length;
                sendCurrentBufferAsPacket(len, c2address);

            } else { // Connected, but not authenticated
                // add message to pending message to be sent

                // send message later
                user.addMessageToQueue(message);

                // FIRST MESSAGE OF THE CC PROTOCOL
                // //////////////////////////////////////////////////////////////////////////////////////////

                SocketAddress c2address = mUsers.getAddress(username);
                Arrays.fill(mBuffer, (byte) 0);
                // create header
                byte[] messageHeader = Utils.getHeaderForMessageType(MessageType.CC_AUTH1);

                // copy header and encrypted message into our buffer
                System.arraycopy(messageHeader, 0, mBuffer, 0, messageHeader.length);

                // copy the encrypted message
                System.arraycopy(mCredentials.getLeft().getBytes(), 0, mBuffer, messageHeader.length, mCredentials.getLeft().getBytes().length);

                // compute length
                int len = messageHeader.length + mCredentials.getLeft().getBytes().length;

                // send!
                sendCurrentBufferAsPacket(len, c2address);

                // //////////////////////////////////////////////////////////////////////////////////////////////
            }
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
            // mUserIo.logDebug("sending packet: " + new
            // String(DatatypeConverter.printBase64Binary(mBuffer)));
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

                // mUserIo.logDebug("received data (receive thread): " +
                // DatatypeConverter.printBase64Binary(mReceiveBuffer));

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
                byte[] csauth2 = Arrays.copyOfRange(mReceiveBuffer, Constants.MESSAGE_HEADER.length + 1, packet.getLength());
                String csauth2decrypted = mCrypto.decryptWithSharedKey(mC1Sym, csauth2);
                String[] csauth2decryptedSplit = csauth2decrypted.split("::");
                if (csauth2decryptedSplit.length != 3)
                    throw new SoChatException("Invalid auth 2 CS message.");
                String rstring = csauth2decryptedSplit[0];
                String sstring = csauth2decryptedSplit[1];
                String nstring = csauth2decryptedSplit[2];

                BigInteger rrec = new BigInteger(rstring, 16);
                byte[] saltrec = DatatypeConverter.parseBase64Binary(sstring);
                int nrec = Integer.parseInt(nstring);

                // check that the R matches to authenticate server
                if (!rrec.equals(mRpriv)) {
                    throw new SoChatException("R mismatch, server compromised.");
                }

                // compute Lamport hash^n-1 of password and send it back
                String passwordBase64 = DatatypeConverter.printBase64Binary(mCredentials.getRight().getBytes("UTF-8"));
                String lamportHash = mCrypto.calculateLamportHash(passwordBase64, saltrec, nrec - 1);
                byte[] encrypted0 = mCrypto.encryptWithSharedKey(mC1Sym, lamportHash);

                Arrays.fill(mBuffer, (byte) 0);
                byte[] messageHeader0 = Utils.getHeaderForMessageType(MessageType.CS_AUTH3);
                System.arraycopy(messageHeader0, 0, mBuffer, 0, messageHeader0.length);
                System.arraycopy(encrypted0, 0, mBuffer, messageHeader0.length, encrypted0.length);
                int len0 = messageHeader0.length + encrypted0.length;
                sendCurrentBufferAsPacketToServer(len0);

                break;
            case CS_AUTH4:
                byte[] csauth4 = Arrays.copyOfRange(mReceiveBuffer, Constants.MESSAGE_HEADER.length + 1, packet.getLength());
                String csauth4decrypted = mCrypto.decryptWithSharedKey(mC1Sym, csauth4);

                if (Constants.AUTH_SUCCESS.equals(csauth4decrypted)) {
                    // let the user have access now that we're logged in
                    mAwaitConnection.countDown();
                    mUserIo.logError(csauth4decrypted);
                } else {
                    mUserIo.logError("Error logging in: " + csauth4decrypted);
                    System.exit(0);
                }

                break;
            case CC_AUTH1:
                // receive from C1: Username
                byte[] ccauth1 = Arrays.copyOfRange(mReceiveBuffer, Constants.MESSAGE_HEADER.length + 1, packet.getLength());
                String c1username = new String(ccauth1, "UTF-8");

                // SECOND MESSAGE OF THE CC PROTOCOL
                // //////////////////////////////////////////////////////////////////////////////////////////
                // if user doesn't exist yet, add him to our user cache
                if (!mUsers.existsUser(c1username)) {
                    mUsers.addUser(c1username, packet.getSocketAddress());
                }
                ClientUserInfo c1 = mUsers.getUserInfo(c1username);
                BigInteger c2nonce = new BigInteger(16, new SecureRandom());
                c1.setN2prime(c2nonce);
                String toencrypt = c1username + "::" + c2nonce.toString(16);
                byte[] encrypted2 = mCrypto.encryptWithSharedKey(mC1Sym, toencrypt);
                Arrays.fill(mBuffer, (byte) 0);
                // create header
                byte[] messageHeader = Utils.getHeaderForMessageType(MessageType.CC_AUTH2);

                // copy header and encrypted message into our buffer
                System.arraycopy(messageHeader, 0, mBuffer, 0, messageHeader.length);

                // copy the encrypted message
                System.arraycopy(encrypted2, 0, mBuffer, messageHeader.length, encrypted2.length);

                // compute length
                int len = messageHeader.length + encrypted2.length;

                // send!
                sendCurrentBufferAsPacket(len, c1.getAddress());

                // //////////////////////////////////////////////////////////////////////////////////////////////

                break;

            case CC_AUTH2:
                byte[] ccauth2 = Arrays.copyOfRange(mReceiveBuffer, Constants.MESSAGE_HEADER.length + 1, packet.getLength());

                // SECOND MESSAGE OF THE CC PROTOCOL
                // //////////////////////////////////////////////////////////////////////////////////////////
                String c2username = mUsers.getUsernameByAddress(packet.getSocketAddress());
                ClientUserInfo c2info = mUsers.getUserInfo(c2username);
                c2info.setN1(new BigInteger(16, new SecureRandom()));
                String ccauth2str = DatatypeConverter.printBase64Binary(ccauth2);
                String toencrypt3 = mCredentials.getLeft() + "::" + c2username + "::" + c2info.getN1() + "::" + ccauth2str;
                byte[] encrypted3 = toencrypt3.getBytes("UTF-8");
                Arrays.fill(mBuffer, (byte) 0);

                // create header
                byte[] messageHeader3 = Utils.getHeaderForMessageType(MessageType.CC_AUTH3);

                // copy header and encrypted message into our buffer
                System.arraycopy(messageHeader3, 0, mBuffer, 0, messageHeader3.length);

                // copy the encrypted message
                System.arraycopy(encrypted3, 0, mBuffer, messageHeader3.length, encrypted3.length);

                // compute length
                int len3 = messageHeader3.length + encrypted3.length;

                // send!
                sendCurrentBufferAsPacketToServer(len3);

                // //////////////////////////////////////////////////////////////////////////////////////////////
                break;

            case CC_AUTH4: // C1Sym{NC1, K12, Username(C2), C2Sym{K12,
                           // Username(C1), N’C2}}
                byte[] ccauth4 = Arrays.copyOfRange(mReceiveBuffer, Constants.MESSAGE_HEADER.length + 1, packet.getLength());

                // FOURTH MESSAGE OF THE CC PROTOCOL
                // //////////////////////////////////////////////////////////////////////////////////////////
                String ccauth4Msg = mCrypto.decryptWithSharedKey(mC1Sym, ccauth4);
                String[] ccauth4MsgSplit = ccauth4Msg.split("::");
                if (ccauth4MsgSplit.length != 4) {
                    throw new SoChatException("Malformed message received during send.");
                }
                String nonceC1 = ccauth4MsgSplit[0];
                byte[] k12Bytes = DatatypeConverter.parseBase64Binary(ccauth4MsgSplit[1]);
                String usernameC2 = ccauth4MsgSplit[2];
                String c2symData = ccauth4MsgSplit[3];
                ClientUserInfo c2 = mUsers.getUserInfo(usernameC2);
                mUserIo.logDebug("C1 now has k12! " + ccauth4MsgSplit[1]);

                c2.setN1(new BigInteger(nonceC1, 16));
                c2.setK12(new SecretKeySpec(k12Bytes, 0, k12Bytes.length, "AES"));
                c2.setC2sym_msg4(c2symData);

                mUserIo.logDebug("Received msg #4: " + ccauth4Msg);
                byte[] c2symDataBytes = DatatypeConverter.parseBase64Binary(c2symData);

                Arrays.fill(mBuffer, (byte) 0);

                // create header
                byte[] messageHeader4 = Utils.getHeaderForMessageType(MessageType.CC_AUTH5);

                // copy header and encrypted message into our buffer
                System.arraycopy(messageHeader4, 0, mBuffer, 0, messageHeader4.length);

                // copy the encrypted message
                System.arraycopy(c2symDataBytes, 0, mBuffer, messageHeader4.length, c2symDataBytes.length);

                // compute length
                int len4 = messageHeader4.length + c2symDataBytes.length;

                // send!
                sendCurrentBufferAsPacket(len4, c2.getAddress());

                // //////////////////////////////////////////////////////////////////////////////////////////////
                break;

            case CC_AUTH5:
                // C1 -> C2: C2Sym{K12, Username(C1), N'C2}
                byte[] ccauth5 = Arrays.copyOfRange(mReceiveBuffer, Constants.MESSAGE_HEADER.length + 1, packet.getLength());
                String username2_5 = mUsers.getUsernameByAddress(packet.getSocketAddress());

                // FIFTH MESSAGE OF THE CC PROTOCOL
                // //////////////////////////////////////////////////////////////////////////////////////////
                mUserIo.logDebug("Trying to decrypt using C2Sym '" + DatatypeConverter.printBase64Binary(mC1Sym.getEncoded()) + "': "
                        + DatatypeConverter.printBase64Binary(ccauth5));
                String ccauth5Msg = mCrypto.decryptWithSharedKey(mC1Sym, ccauth5);
                String[] ccauth5MsgSplit = ccauth5Msg.split("::");
                if (ccauth5MsgSplit.length != 3) {
                    throw new SoChatException("Malformed message received during send.");
                }
                if (!ccauth5MsgSplit[1].equals(username2_5)) {
                    throw new SoChatException("Username doesn't match. Someone may be hacking the protocol!");
                }

                String k12 = ccauth5MsgSplit[0];
                byte[] k12bytes = DatatypeConverter.parseBase64Binary(k12);
                mUserIo.logDebug("C2 now has k12! " + k12);
                BigInteger nonceC2prime = new BigInteger(ccauth5MsgSplit[2], 16);
                ClientUserInfo user2 = mUsers.getUserInfo(username2_5);
                mUserIo.logDebug("--- nonceC2prime: " + nonceC2prime.toString(16) + "; user2.getN2prime(): " + user2.getN2prime().toString(16));
                if (!nonceC2prime.equals(user2.getN2prime())) {
                    throw new SoChatException("NC'2 mismatch. Someone may be hacking around!");
                }
                user2.setK12(new SecretKeySpec(k12bytes, 0, k12bytes.length, "AES"));

                // now, send out a new nonce encrypted with K12
                BigInteger nc2 = new BigInteger(16, new SecureRandom());
                user2.setN2(nc2);
                byte[] k12_nc2Bytes = mCrypto.encryptWithSharedKey(user2.getK12(), nc2.toString(16));

                Arrays.fill(mBuffer, (byte) 0);

                // create header
                byte[] messageHeader5 = Utils.getHeaderForMessageType(MessageType.CC_AUTH6);

                // copy header and encrypted message into our buffer
                System.arraycopy(messageHeader5, 0, mBuffer, 0, messageHeader5.length);

                // copy the encrypted message
                System.arraycopy(k12_nc2Bytes, 0, mBuffer, messageHeader5.length, k12_nc2Bytes.length);

                // compute length
                int len5 = messageHeader5.length + k12_nc2Bytes.length;

                // send!
                sendCurrentBufferAsPacket(len5, user2.getAddress());

                break;

            case CC_AUTH6: {
                // receive C2 -> C1: K12{NC2}
                String senderusername = mUsers.getUsernameByAddress(packet.getSocketAddress());
                ClientUserInfo u6 = mUsers.getUserInfo(senderusername);
                byte[] ccauth6 = Arrays.copyOfRange(mReceiveBuffer, Constants.MESSAGE_HEADER.length + 1, packet.getLength());
                String nc2ccauth6 = mCrypto.decryptWithSharedKey(u6.getK12(), ccauth6);
                BigInteger nc2ccauth6bigint = new BigInteger(nc2ccauth6, 16);
                BigInteger nc2ccauth6bigintdec = nc2ccauth6bigint.subtract(BigInteger.ONE);
                byte[] encryptedccauth7 = mCrypto.encryptWithSharedKey(u6.getK12(), nc2ccauth6bigintdec.toString(16));

                // mark user as authenticated
                u6.setAuthenticated(true);
                mUserIo.logDebug("Now authenticated " + u6.getUsername());

                // send out pending messages
                String msg;
                while ((msg = u6.getMessageQueue().poll()) != null)
                    sendMessage(u6.getUsername(), msg);

                Arrays.fill(mBuffer, (byte) 0);

                // create header
                byte[] messageHeader45 = Utils.getHeaderForMessageType(MessageType.CC_AUTH7);
                System.arraycopy(messageHeader45, 0, mBuffer, 0, messageHeader45.length);
                System.arraycopy(encryptedccauth7, 0, mBuffer, messageHeader45.length, encryptedccauth7.length);
                int len45 = messageHeader45.length + encryptedccauth7.length;
                sendCurrentBufferAsPacket(len45, packet.getSocketAddress());

                break;
            }
            case CC_AUTH7: {
                // C1 -> C2: K12{NC2-1}
                String recipientusername = mUsers.getUsernameByAddress(packet.getSocketAddress());
                ClientUserInfo u7 = mUsers.getUserInfo(recipientusername);
                byte[] ccauth7 = Arrays.copyOfRange(mReceiveBuffer, Constants.MESSAGE_HEADER.length + 1, packet.getLength());
                String nc2minusOneccauth7 = mCrypto.decryptWithSharedKey(u7.getK12(), ccauth7);
                BigInteger nc2minusOneccauth7bigint = new BigInteger(nc2minusOneccauth7, 16);
                BigInteger nc2minusOneccauth7bigintinc = nc2minusOneccauth7bigint.add(BigInteger.ONE);
                if (!nc2minusOneccauth7bigintinc.equals(u7.getN2()))
                    throw new SoChatException("Failed to establish connection with " + recipientusername);

                // mark authenticated
                u7.setAuthenticated(true);
                mUserIo.logDebug("Now authenticated " + recipientusername);

                // send out pending messages
                String msg;
                while ((msg = u7.getMessageQueue().poll()) != null)
                    sendMessage(u7.getUsername(), msg);

                break;
            }

            case CC_MESSAGE: {
                // Encrypt message with K12 and send it out
                byte[] ccMsg = Arrays.copyOfRange(mReceiveBuffer, Constants.MESSAGE_HEADER.length + 1, packet.getLength());
                String usernameM = mUsers.getUsernameByAddress(packet.getSocketAddress());
                ClientUserInfo uM = mUsers.getUserInfo(usernameM);
                String decryptedMsg = mCrypto.decryptWithSharedKey(uM.getK12(), ccMsg);

                mUserIo.logMessage("<From " + usernameM + ">: " + decryptedMsg);

                break;

            }

            case CMD_LIST_RESPONSE: {
                byte[] encrypted = Arrays.copyOfRange(mReceiveBuffer, Constants.MESSAGE_HEADER.length + 1, packet.getLength());

                // decrypt data
                String decrypted = mCrypto.decryptWithSharedKey(mC1Sym, encrypted);
                mUserIo.logDebug("Received list response from server: " + decrypted);

                String[] info = decrypted.split("::");
                BigInteger r = new BigInteger(info[0], 16);
                String list = info[1];

                // check that R matches
                if ((r.equals(mLastListCommandR)) == false) {
                    // System.out.println("r = " + r);
                    // System.out.println("mLastListCommandR = " +
                    // mLastListCommandR);
                    r = null;
                    throw new SoChatException("Stray list response received!");
                } else {
                    mUserIo.logMessage("Online users:\n" + list);
                    mUsers.updateList(list);
                    r = null;
                }

                break;
            }
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
