package com.olegvaskevich.chat.server;

import java.net.InetAddress;

/**
 * POJO that contains the data we need to send clients messages.
 */
public class ChatClientInfo {

    private final InetAddress ip;
    private final int port;

    public ChatClientInfo(InetAddress ip, int port) {
        this.ip = ip;
        this.port = port;
    }

    public InetAddress getIp() {
        return ip;
    }

    public int getPort() {
        return port;
    }

}
