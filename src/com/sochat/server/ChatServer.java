package com.sochat.server;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.LinkedHashSet;
import java.util.Set;

import com.sochat.shared.Constants;
import com.sochat.shared.StandardUserIO;
import com.sochat.shared.UserIO;
import com.sochat.shared.Utils;
import com.sochat.shared.Constants.MessageType;

/**
 * Class that contains the chat server, which can receive GREETING messages from
 * a theoretically unlimited number of clients as well as broadcast messages
 * sent from individual chat clients to all the other connected chat clients.
 * 
 * @author Oleg, Saba
 */
public class ChatServer implements Runnable {

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
     * Use a LinkedHashSet to keep track of connected clients, because we don't
     * want duplicates and we want to be able to iterate over the set in order
     * to broadcast messages.
     */
    private final Set<ChatClientInfo> mClients = new LinkedHashSet<ChatClientInfo>();

    /**
     * The logger this server will use to print messages.
     */
    private final UserIO mLogger;

    /**
     * Creates a new chat server running on the specified port.
     * 
     * @param port
     * @param logger
     *            the logger to use to save messages
     * @throws IOException
     *             Thrown if there was an issue connecting to the socket.
     */
    public ChatServer(int port, UserIO logger) throws IOException {
        mLogger = logger;
        mLogger.logMessage("Starting ChatServer...");
        mPort = port;
        mSocket = new DatagramSocket(mPort);
        mLogger.logMessage("Running on " + mSocket.getLocalAddress() + ":" + mSocket.getLocalPort() + "...");
    }

    /**
     * Runs the chat server, waiting for new messages.
     */
    public void run() {
        mLogger.logMessage("Server initialized...");

        // wait for data on the UDP socket
        while (true) {
            DatagramPacket packet = new DatagramPacket(mBuffer, mBuffer.length);
            try {
                mSocket.receive(packet);
            } catch (IOException e) {
                mLogger.logError("Error receiving packet " + packet + ": " + e);
                //e.printStackTrace();
                continue;
            }

            int len = packet.getLength();
            byte[] buffer = packet.getData();

            int contentOffset = Constants.MESSAGE_HEADER.length + 1;
            int contentLen = packet.getLength() - contentOffset;

            // check that the length seems valid (header + message type byte)
            if (len < Constants.MESSAGE_HEADER.length + 1) {
                mLogger.logMessage("Invalid message received.");
                continue;
            }

            // check that version matches
            if (!Utils.arrayEquals(Constants.MESSAGE_HEADER, 0, buffer, 0, Constants.MESSAGE_HEADER.length)) {
                mLogger.logMessage("Packet received is not a Chat packet or is from an old version.");
                continue;
            }

            // the next byte contains the message type
            byte messageType = buffer[contentOffset - 1];
            if (messageType < 0 || messageType >= MessageType.values().length) {
                mLogger.logMessage("Invalid message type " + messageType);
                continue;
            }

            // parse the message depending on its type
            MessageType type = MessageType.values()[messageType];
            switch (type) {
            case GREETING:
                // add this client to our set of connected clients
                mLogger.logMessage("Accepted new client at " + packet.getAddress().getHostAddress() + ":"
                        + packet.getPort());
                mClients.add(new ChatClientInfo(packet.getAddress(), packet.getPort()));
                break;

            case MESSAGE:
                // read the received message
                String message = new String(buffer, contentOffset, contentLen);
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
                    DatagramPacket sendPacket = new DatagramPacket(buffer, contentOffset
                            + msgToSendBytes.length, client.getIp(), client.getPort());
                    try {
                        mSocket.send(sendPacket);
                    } catch (IOException e) {
                        mLogger.logError("Error sending packet " + packet + ": " + e);
                        //e.printStackTrace();
                        continue;
                    }
                }
                break;

            default:
                mLogger.logError("Unhandled message type " + type.name());
                break;
            }
        }
    }

    public int getPort() {
        return mPort;
    }

    public void stop() {
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
            server.run();
        } catch (IOException | SecurityException e) {
            System.err.println("ChatServer encountered an error! Exiting.");
            e.printStackTrace();
        }
    }

    private static void printUsage() {
    	  System.out.println("SOChat, by Oleg and Saba for CS4740 final project\n\n"
                  + "usage: java SOChatServer serverPort\n\n"
                  + "Report bugs to me@olegvaskevich.com.");
    }

}
