package com.sochat.server;

import com.sochat.server.db.UserDatabase;
import com.sochat.shared.Constants.MessageType;

public class ClientAuthenticator {

    private final UserDatabase mDb;

    public ClientAuthenticator(UserDatabase db) {
        mDb = db;
    }

    /**
     * Handles authentication as needed for the given message.
     * 
     * @param type
     */
    public void handleAuth(MessageType type) {
        switch (type) {
        case CS_AUTH1:
            
            break;
        case CS_AUTH3:
            break;
        default:
            
        }
    }

}
