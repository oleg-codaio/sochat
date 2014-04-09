package com.sochat;

import java.io.IOException;
import java.util.concurrent.SynchronousQueue;

import com.sochat.shared.io.UserIO;

/**
 * Logger that records the last message logged so that we can check it in a unit test, and also lets us feed new
 * messages in.
 * 
 * @author Oleg Vaskevich
 */
public class LastMessageSilentUserIO extends UserIO {

    private String mLastMessage = null;
    private SynchronousQueue<String> mFeedMessage = new SynchronousQueue<>();

    public String getLastMessage() {
        return mLastMessage;
    }

    /**
     * Sends a message to this UserIO that will be passed on as if it was entered by the user.
     */
    public void feedMessage(String message) {
        mFeedMessage.add(message);
    }

    @Override
    public void logMessage(String msg) {
        mLastMessage = msg;
    }

    @Override
    public void logError(String err) {
        mLastMessage = err;
    }

    @Override
    public String readLineBlocking() throws IOException {
        try {
            return mFeedMessage.take();
        } catch (InterruptedException e) {
            // rethrow as IOException
            throw new IOException(e);
        }
    }

}
