package com.sochat.shared;

import java.net.SocketAddress;

/**
 * Basic class that contains the basic user info: username and associated socket
 * address (IP address + port).
 */
public abstract class UserInfo {

    private final String username;
    private SocketAddress addr;

    protected UserInfo(String username) {
        this.username = username;
    }

    public String getUsername() {
        return username;
    }

    public SocketAddress getAddress() {
        return addr;
    }

    public void setLastAddress(SocketAddress addr) {
        this.addr = addr;
    }

    public void clearAddress() {
        addr = null;
    }

}
