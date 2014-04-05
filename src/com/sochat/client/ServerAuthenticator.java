package com.sochat.client;

import com.sochat.shared.Constants;
import com.sochat.shared.Constants.MessageType;

public class ServerAuthenticator {

    public void initAuth() {
        
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
