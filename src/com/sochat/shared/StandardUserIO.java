package com.sochat.shared;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * Logger that simply uses the standard system output and input.
 * 
 * @author Oleg Vaskevich
 */
public class StandardUserIO extends UserIO {

    BufferedReader mReader = new BufferedReader(new InputStreamReader(System.in));

    @Override
    public void logMessage(String msg) {
        System.out.println(msg);
    }

    @Override
    public void logError(String err) {
        System.err.println(err);
    }

    @Override
    public String readLineBlocking() {
        try {
            return mReader.readLine();
        } catch (IOException e) {
            logError("Encountered error while reading input.");
            // Yes this is bad, but if some I/O error happens here we can just
            // crash for now. In a production app, I would likely show an error
            // dialog and exit.
            throw new RuntimeException(e);
        }
    }

}
