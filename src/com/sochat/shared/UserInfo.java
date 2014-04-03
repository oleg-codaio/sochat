package com.sochat.shared;

import java.net.InetSocketAddress;

/**
 * Basic class that contains the basic user info: username and associated socket
 * address (IP address + port).
 */
public abstract class UserInfo {

    private final String username;
    private InetSocketAddress lastAddr;

    protected UserInfo(String username) {
        this.username = username;
    }

    public String getUsername() {
        return username;
    }

    public InetSocketAddress getLastAddress() {
        return lastAddr;
    }

    public void setLastAddress(InetSocketAddress lastAddr) {
        this.lastAddr = lastAddr;
    }

}
