package com.sochat.client;

import java.io.IOException;

import org.apache.commons.lang3.tuple.Pair;

import com.sochat.shared.io.UserIO;

public class ClientInputReader {

    private UserIO mIo;

    public ClientInputReader(UserIO io) {
        mIo = io;
    }

    public Pair<String, String> readCredentials() {
        String username, password;

        try {
            mIo.logMessage("Enter your username: ");
            username = mIo.readLineBlocking();

            if (username.contains(":")) {
                mIo.logError("Username cannot contain colon.");
                return null;
            }

            if (username.length() > 20) {
                mIo.logError("Username is too long.");
                return null;
            }

            System.out.print("Enter your password: ");
            password = mIo.readLineBlocking();
        } catch (IOException e) {
            mIo.logError(e.toString());
            return null;
        }

        return Pair.of(username, password);
    }

}
