package com.sochat.client.db;

import java.math.BigInteger;
import java.net.SocketAddress;
import java.util.LinkedList;
import java.util.Queue;

import javax.crypto.SecretKey;

import com.sochat.shared.UserInfo;

/**
 * Package-private class that also contains server-pertinent user info. This POJO is used internally in the user
 * database.
 */
public class ClientUserInfo extends UserInfo {

    private SecretKey k12;

    // if this client is C1:
    private String c2sym_msg2; // C2Sym{Username(C1), N’C2}

    private BigInteger n1, n2prime, n2;
    private String c2sym_msg4; // C2Sym{K12, Username(C1), N’C2}

    private Queue<String> messagesToSend = new LinkedList<>();

    // if this client is C2, only needs to know secret key and nc2

    private boolean isAuthenticated = false;

    public static ClientUserInfo create(String username, SocketAddress addr) {
        return new ClientUserInfo(username, addr);
    }

    private ClientUserInfo(String username, SocketAddress addr) {
        super(username);
        setAddress(addr);
    }

    public boolean isAuthenticated() {
        return isAuthenticated;
    }

    public void setAuthenticated(boolean authenticated) {
        isAuthenticated = authenticated;
    }

    public SecretKey getK12() {
        return k12;
    }

    public void setK12(SecretKey k12) {
        this.k12 = k12;
    }

    public String getC2sym_msg2() {
        return c2sym_msg2;
    }

    public void setC2sym_msg2(String c2sym_msg2) {
        this.c2sym_msg2 = c2sym_msg2;
    }

    public BigInteger getN1() {
        return n1;
    }

    public void setN1(BigInteger n1) {
        this.n1 = n1;
    }

    public BigInteger getN2prime() {
        return n2prime;
    }

    public void setN2prime(BigInteger n2prime) {
        this.n2prime = n2prime;
    }

    public BigInteger getN2() {
        return n2;
    }

    public void setN2(BigInteger n2) {
        this.n2 = n2;
    }

    public String getC2sym_msg4() {
        return c2sym_msg4;
    }

    public void setC2sym_msg4(String c2sym_msg4) {
        this.c2sym_msg4 = c2sym_msg4;
    }

    public void addMessageToQueue(String message) {
        messagesToSend.add(message);
    }

    public Queue<String> getMessageQueue() {
        return messagesToSend;
    }
}
