package com.sochat.client.db;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.HashMap;

import com.sochat.shared.SoChatException;

/**
 * Class that emulates an in-memory database that contains user credentials as
 * well as their connection status.
 * 
 * @author Oleg
 */
public class ClientUserCache {

    /**
     * Username <-> User info
     */
    private HashMap<String, ClientUserInfo> mUsersByUsername = new HashMap<>();

    /**
     * Socket address <-> User info
     */
    private HashMap<SocketAddress, ClientUserInfo> mUsersByAddress = new HashMap<>();

    public ClientUserCache() {
        // empty constructor
    }

    /**
     * Updates the DB with the new socket address of the user.
     * 
     * @param username
     * @param address
     */
    public void addUser(String username, SocketAddress address) {
        ClientUserInfo info = ClientUserInfo.create(username, address);
        mUsersByAddress.put(address, info);
        mUsersByUsername.put(username, info);
    }

    // public void removeUser(String username) {
    // mUsersByAddress.remove(username);
    // }

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
        ClientUserInfo info = mUsersByAddress.get(address);
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
        ClientUserInfo u = mUsersByUsername.get(username);
        return (u != null && u.getK12() != null && u.isAuthenticated());
    }

    public void setUserAuthenticated(String username, boolean authenticated) throws SoChatException {
        ClientUserInfo u = mUsersByUsername.get(username);
        if (u == null)
            throw new SoChatException("No such user " + username + " in database.");

        u.setAuthenticated(true);
    }

    /**
     * Updates the database with the latest output of the "list" command from
     * the server.
     * 
     * @param list
     * @throws SoChatException
     */
    public void updateList(String list) throws SoChatException {
        // TODO: remove disconnected users from database?

        // split list into username:ipaddress:port
        String[] users = list.split("\n");
        for (String user : users) {
            String[] userInfo = user.split(":");
            if (userInfo.length != 3)
                throw new SoChatException("Invalid user format");
            String username = userInfo[0].trim();
            String ip = userInfo[1].trim();
            String port = userInfo[2].trim();

            SocketAddress addr = new InetSocketAddress(ip, Integer.parseInt(port));
            if (!mUsersByUsername.containsKey(username)) {
                // add user if it doesn't exist
                addUser(username, addr);
            } else {
                // otherwise, update user's IP address
                mUsersByUsername.get(username).setAddress(addr);
            }
        }
    }

    public SocketAddress getAddress(String username) throws SoChatException {
        if (!mUsersByUsername.containsKey(username))
            throw new SoChatException("No such username for getAddress");
        return mUsersByUsername.get(username).getAddress();
    }

    public ClientUserInfo getUserInfo(String username) throws SoChatException {
        if (!mUsersByUsername.containsKey(username))
            throw new SoChatException("No such username for getUserInfo");
        return mUsersByUsername.get(username);
    }
}
