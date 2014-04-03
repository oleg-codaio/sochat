package com.sochat.server.db;

import com.sochat.shared.UserInfo;

/**
 * Package-private class that also contains server-pertinent user info. This
 * POJO is used internally in the user database.
 */
class ServerUserInfo extends UserInfo {

    private String passwordHash;

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

}
