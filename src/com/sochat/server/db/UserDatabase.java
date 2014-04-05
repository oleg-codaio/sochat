package com.sochat.server.db;

import java.net.InetSocketAddress;
import java.util.HashMap;

/**
 * Class that emulates an in-memory database that contains user credentials as
 * well as their connection status.
 * 
 * @author Oleg
 */
public class UserDatabase {

    /**
     * Username <-> User info
     */
    private HashMap<String, ServerUserInfo> mUsersByUsername = new HashMap<>();

    /**
     * Socket address <-> User info
     */
    private HashMap<InetSocketAddress, ServerUserInfo> mUsersByAddress = new HashMap<>();

    public UserDatabase() {
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
    public void addUserAddress(String username, InetSocketAddress address) {
        if (!mUsersByAddress.containsKey(username))
            throw new IllegalArgumentException("Username does not exist in server DB.");
        ServerUserInfo info = mUsersByUsername.get(username);
        info.setLastAddress(address);
        mUsersByAddress.put(address, info);
    }

    public void clearUserAddress(String username) {
        if (!mUsersByAddress.containsKey(username))
            throw new IllegalArgumentException("Username does not exist in server DB.");
        mUsersByAddress.remove(mUsersByAddress.get(username));
        ServerUserInfo info = mUsersByUsername.get(username);
        info.clearLastAddress();
    }

    /**
     * Returns the username associated with a given socket address.
     * 
     * @param address
     * @return
     */
    public String getUsernameByAddress(InetSocketAddress address) {
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
}
