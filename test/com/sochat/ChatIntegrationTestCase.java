package com.sochat;

import java.net.InetAddress;

import junit.framework.TestCase;

import com.sochat.client.ChatClient;
import com.sochat.server.ChatServer;

public class ChatIntegrationTestCase extends TestCase {

    private static final int NUM_CLIENTS = 10;
    private static final int SERVER_PORT = 9900;
    private static final long SLEEP_WAIT = 100; // increase delay if test cases fail
    private static InetAddress LOCALHOST;

    private ChatServer mServer;
    private ChatClient[] mChatClients = new ChatClient[NUM_CLIENTS];
    private Thread[] childThreads = new Thread[NUM_CLIENTS + 1];
    private LastMessageSilentUserIO[] userIOs = new LastMessageSilentUserIO[NUM_CLIENTS + 1];

    @Override
    protected void setUp() throws Exception {
        LOCALHOST = InetAddress.getLocalHost();

        // initialize the user IOs that we can use to keep track of individual
        // outputs as well as feed inputs to chat clients. This is needed
        // because we are running this test case in the same global instance, so
        // System.out and System.in cannot easily be distinctly used.
        for (int i = 0; i < userIOs.length; ++i) {
            userIOs[i] = new LastMessageSilentUserIO();
        }

        // now create the server and chat client objects
        mServer = new ChatServer(SERVER_PORT, userIOs[0]);
        for (int i = 0; i < NUM_CLIENTS; ++i) {
            mChatClients[i] = new ChatClient(LOCALHOST, SERVER_PORT, userIOs[i + 1]);
        }

        // create threads for each object (each chat client will create its own
        // child thread too)
        for (int i = 0; i < childThreads.length; ++i) {
            childThreads[i] = new Thread(i == 0 ? mServer : mChatClients[i - 1]);
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void tearDown() throws Exception {
        mServer.stop();
        mServer = null;
        for (ChatClient client : mChatClients) {
            client.stop();
        }
        mChatClients = null;
        for (Thread thread : childThreads) {
            thread.stop();
        }
        childThreads = null;
        userIOs = null;
        Thread.sleep(SLEEP_WAIT);
    }

    public void testServerStarts() throws Exception {
        childThreads[0].start();
        Thread.sleep(SLEEP_WAIT);

        assertEquals("Server initialized...", userIOs[0].getLastMessage());
    }

    public void testSingleClientConnects() throws Exception {
        childThreads[0].start();
        Thread.sleep(SLEEP_WAIT);
        childThreads[1].start();
        Thread.sleep(SLEEP_WAIT);

        assertEquals("Client initialized! Type a message and press enter to send it to the server.",
                userIOs[1].getLastMessage());
        assertEquals(
                "Accepted new client at " + LOCALHOST.getHostAddress() + ":" + mChatClients[0].getPort(),
                userIOs[0].getLastMessage());
    }

    public void testMultipleClientsConnect() throws Exception {
        for (int i = 0; i < childThreads.length; ++i) {
            childThreads[i].start();
            Thread.sleep(SLEEP_WAIT);

            if (i > 0) {
                // test server and client
                assertEquals("Accepted new client at " + LOCALHOST.getHostAddress() + ":"
                        + mChatClients[i - 1].getPort(), userIOs[0].getLastMessage());
                assertEquals("Client initialized! Type a message and press enter to send it to the server.",
                        userIOs[i].getLastMessage());
            }

        }
    }

    public void testMessageBroadcastedToAllClients() throws Exception {
        for (int i = 0; i < childThreads.length; ++i) {
            childThreads[i].start();
            Thread.sleep(SLEEP_WAIT);
        }

        final String MSG = "Test message from first-connected chat client!";
        userIOs[1].feedMessage(MSG);
        Thread.sleep(SLEEP_WAIT);

        // verify server message
        assertEquals(
                "Broadcasting message from /" + LOCALHOST.getHostAddress() + ":" + mChatClients[0].getPort()
                        + ": \"" + MSG + "\"", userIOs[0].getLastMessage());

        // verify all clients received
        for (int i = 0; i < mChatClients.length; ++i) {
            assertEquals("<From /" + LOCALHOST.getHostAddress() + ":" + mChatClients[0].getPort() + ">: " + MSG,
                    userIOs[i + 1].getLastMessage());
        }
    }

}
