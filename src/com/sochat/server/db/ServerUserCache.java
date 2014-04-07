package com.sochat.server.db;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.HashMap;

import javax.crypto.SecretKey;

import com.sochat.shared.SoChatException;

/**
 * Class that emulates an in-memory database that contains user credentials as
 * well as their connection status.
 * 
 * @author Oleg
 */
public class ServerUserCache {

    /**
     * Username <-> User info
     */
    private HashMap<String, ServerUserInfo> mUsersByUsername = new HashMap<>();

    /**
     * Socket address <-> User info
     */
    private HashMap<SocketAddress, ServerUserInfo> mUsersByAddress = new HashMap<>();

    public ServerUserCache() {
        // initialize with default entries
        addUser("saba", "sabapassword");
        addUser("oleg", "olegpassword");
        addUser("guevara", "guevpassword");
        addUser("amirali", "amirpassword");
    }

    /**
     * Adds user to the database, replacing/updating as needed.
     * 
     * @param username
     * @param password
     */
    public void addUser(String username, String password) {
        mUsersByUsername.put(username, ServerUserInfo.create(username, password));
    }

    /**
     * Updates the DB with the new socket address of the user.
     * 
     * @param username
     * @param address
     */
    public void addUserAddress(String username, SocketAddress address) {
        if (!mUsersByUsername.containsKey(username))
            throw new IllegalArgumentException("Username does not exist in server DB.");
        ServerUserInfo info = mUsersByUsername.get(username);
        info.setAddress(address);
        mUsersByAddress.put(address, info);
    }

    public void clearUserAddress(String username) {
        if (!mUsersByAddress.containsKey(username))
            throw new IllegalArgumentException("Username does not exist in server DB.");
        mUsersByAddress.remove(mUsersByAddress.get(username));
        ServerUserInfo info = mUsersByUsername.get(username);
        info.clearAddress();
    }

    public boolean existsUser(String username) {
        return mUsersByUsername.containsKey(username);
    }

    /**
     * Returns the username associated with a given socket address.
     * 
     * @param address
     * @return
     */
    public String getUsernameByAddress(SocketAddress address) {
        ServerUserInfo info = mUsersByAddress.get(address);
        return info == null ? null : info.getUsername();
    }

    /**
     * Returns if a user is connected.
     * 
     * @param username
     * @return
     */
    public boolean isUserConnected(String username) {
        return mUsersByAddress.containsKey(username);
    }

    public boolean isUserAuthenticated(String username) {
        ServerUserInfo u = mUsersByUsername.get(username);
        return (u != null && u.getC1Sym() != null && u.isAuthenticated());
    }

    public void setUserAuthenticated(String username, boolean authenticated) throws SoChatException {
        ServerUserInfo u = mUsersByUsername.get(username);
        if (u == null)
            throw new SoChatException("No such user " + username + " in database.");

        u.setAuthenticated(true);
    }

    public String getListOfConnectedUsers() {
        StringBuilder b = new StringBuilder();
        for (ServerUserInfo s : mUsersByAddress.values()) {
            if (s.isAuthenticated()) {
                b.append(s.getUsername());
                b.append(":");
                InetSocketAddress addr = (InetSocketAddress) s.getAddress();
                b.append(addr.getAddress().getHostAddress());
                b.append(":");
                b.append(addr.getPort());
                b.append('\n');
            }
        }
        return b.toString().trim();
    }

    public void setUserC1sym(String username, SecretKey c1sym) throws SoChatException {
        ServerUserInfo s = mUsersByUsername.get(username);
        if (s == null)
            throw new SoChatException("No such user " + username + " in database when setting C1Sym.");
        s.setC1Sym(c1sym);
    }

    public SecretKey getUserC1sym(String username) throws SoChatException {
        ServerUserInfo s = mUsersByUsername.get(username);
        if (s == null)
            throw new SoChatException("No such user " + username + " in database when setting C1Sym.");
        return s.getC1Sym();
    }
}
