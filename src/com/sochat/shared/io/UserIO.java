package com.sochat.shared.io;

import java.io.IOException;

/**
 * Abstract class used for logging and input. This makes it easier to change the
 * output of the clients to something else in the future.
 * 
 * @author Oleg Vaskevich
 */
public abstract class UserIO {

    private static boolean ENABLE_DEBUG = true;

    public abstract void logMessage(String msg);

    public abstract void logError(String err);

    public abstract String readLineBlocking() throws IOException;

    public void logDebug(String info) {
        if (ENABLE_DEBUG)
            System.out.println("[DEBUG] " + info);
    }
}
