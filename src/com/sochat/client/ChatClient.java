package com.sochat.client;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;

import com.sochat.shared.Constants;
import com.sochat.shared.StandardUserIO;
import com.sochat.shared.UserIO;
import com.sochat.shared.Utils;
import com.sochat.shared.Constants.MessageType;

/**
 * Class that contains the chat client, which can send the GREETING message to
 * establish a connection to a chat server as well as send the chat server a
 * message to be sent to other chat servers.
 * 
 * @author Oleg, Saba
 */
public class ChatClient implements Runnable {

    /**
     * The socket the client uses to listen for a particular port and dispatch
     * messages.
     */
    private final DatagramSocket mSocket;

    /**
     * The address on which the server is running.
     */
    private final InetAddress mServerAddress;

    /**
     * The port to which this client will connect.
     */
    private final int mServerPort;

    /**
     * Create a buffer that will be used for sending/receiving UDP packets.
     */
    private final byte[] mBuffer = new byte[Constants.MAX_MESSAGE_LENGTH];

    /**
     * The logger this server will use to print messages.
     */
    private final UserIO mUserIO;

    /**
     * Creates a new chat client running on the specified port.
     * 
     * @param port
     * @throws IOException
     *             Thrown if there was an issue connecting to the socket.
     */
    public ChatClient(InetAddress serverAddress, int serverPort, UserIO logger) throws IOException {
        mUserIO = logger;
        mUserIO.logMessage("Starting ChatClient...");
        mServerAddress = serverAddress;
        mServerPort = serverPort;
        mSocket = new DatagramSocket(); // bind to wildcard port
        mUserIO.logMessage("Listening on port " + mSocket.getLocalPort() + "...");
    }

    /**
     * Runs the chat client, spawning child worker thread for each connection
     * and processing new messages.
     */
    public void run() {
        // start listener thread
        new PrintReceivedMessagesThread().start();

        // send GREETING to server
        mUserIO.logMessage("Attaching to server " + mServerAddress + ":" + mServerPort + "...");
        byte[] attachBuffer = { Constants.MESSAGE_HEADER[0], Constants.MESSAGE_HEADER[1],
                Constants.MESSAGE_HEADER[2], Constants.MESSAGE_HEADER[3],
                (byte) MessageType.GREETING.ordinal() };
        DatagramPacket attachPacket = new DatagramPacket(attachBuffer, attachBuffer.length, mServerAddress,
                mServerPort);
        try {
            mSocket.send(attachPacket);
        } catch (IOException e) {
            mUserIO.logError("Error sending GREETING to server: " + e);
            // e.printStackTrace();
            return;
        }

        mUserIO.logMessage("Client initialized! Type a message and press enter to send it to the server.");

        // wait for user to enter text, then send it to the server
        String line;
        while (true) {
            // create a new MESSAGE message with the user's text
            // mLogger.logMessage("> "); // don't use this for now
            try {
                line = mUserIO.readLineBlocking().trim();
            } catch (IOException e) {
                mUserIO.logError("Error sending MESSAGE to server: " + e);
                // e.printStackTrace();
                continue;
            }
            byte lineBytes[] = line.getBytes();
            int contentOffset = Constants.MESSAGE_HEADER.length + 1;
            if (lineBytes.length >= lineBytes.length + contentOffset) {
                mUserIO.logMessage("ERROR: Message not sent because it is too long.");
                continue;
            }
            // add the header, message type, then the message
            System.arraycopy(Constants.MESSAGE_HEADER, 0, mBuffer, 0, contentOffset - 1);
            mBuffer[contentOffset - 1] = (byte) MessageType.MESSAGE.ordinal();
            System.arraycopy(lineBytes, 0, mBuffer, contentOffset, lineBytes.length);

            // send it!
            DatagramPacket packet = new DatagramPacket(mBuffer, contentOffset + lineBytes.length,
                    mServerAddress, mServerPort);
            try {
                mSocket.send(packet);
            } catch (IOException e) {
                mUserIO.logError("Error sending packet " + packet + ": " + e);
                // e.printStackTrace();
                continue;
            }

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
    private class PrintReceivedMessagesThread extends Thread {

        @Override
        public void run() {
            while (true) {
                DatagramPacket packet = new DatagramPacket(mBuffer, mBuffer.length);
                try {
                    mSocket.receive(packet);
                } catch (IOException e) {
                    mUserIO.logError("Error receiving packet " + packet + ": " + e);
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
                    mUserIO.logMessage("Invalid message received.");
                    continue;
                }

                // check that version matches
                if (!Utils.arrayEquals(Constants.MESSAGE_HEADER, 0, buffer, 0,
                        Constants.MESSAGE_HEADER.length)) {
                    mUserIO.logMessage("Packet received is not a Chat packet or is from an old version.");
                    continue;
                }

                // the next byte contains the message type
                byte messageType = buffer[contentOffset - 1];
                if (messageType < 0 || messageType >= MessageType.values().length) {
                    mUserIO.logMessage("Invalid message type " + messageType);
                    continue;
                }

                // parse the message depending on its type
                MessageType type = MessageType.values()[messageType];
                switch (type) {
                case INCOMING:
                    // print the incoming message
                    String msg = new String(packet.getData(), contentOffset, contentLen);
                    mUserIO.logMessage(msg);
                    break;

                default:
                    mUserIO.logMessage("Unhandled message type " + type.name());
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

        ChatClient server;
        try {
            server = new ChatClient(serverAddress, serverPort, new StandardUserIO());
            server.run();
        } catch (IOException | SecurityException e) {
            System.err.println("ChatClient encountered an error! Exiting.");
            e.printStackTrace();
        }
    }

    private static void printUsage() {
        System.out.println("ChatClient, by Oleg Vaskevich for CS4740 (1/26/2014)\n\n"
                + "usage: java ChatClient serverIpAddress serverPort\n\n"
                + "Report bugs to me@olegvaskevich.com.");
    }

}
