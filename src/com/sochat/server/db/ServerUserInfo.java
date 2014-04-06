package com.sochat.server.db;

import javax.crypto.SecretKey;

import com.sochat.shared.UserInfo;

/**
 * Package-private class that also contains server-pertinent user info. This
 * POJO is used internally in the user database.
 */
class ServerUserInfo extends UserInfo {

    private String passwordHash;

    /**
     * Session key - this will be forgotten when the user logs out or server
     * shuts down.
     */
    private SecretKey c1Sym;

    private boolean isAuthenticated = false;

    public static ServerUserInfo create(String username, String password) {
        ServerUserInfo info = new ServerUserInfo(username);
        info.setPasswordHash("TODO");
        // TODO calculate password hash, add info for Lambert's, etc...

        return info;
    }

    private ServerUserInfo(String username) {
        super(username);
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public boolean isConnected() {
        return getAddress() != null;
    }

    public boolean isAuthenticated() {
        return isAuthenticated;
    }

    public void setAuthenticated(boolean authenticated) {
        isAuthenticated = authenticated;
    }

    public SecretKey getC1Sym() {
        return c1Sym;

    }

    public void setC1Sym(SecretKey c1Sym) {
        this.c1Sym = c1Sym;
    }

}
