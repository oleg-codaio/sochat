package com.sochat.shared;

public final class Constants {

    /**
     * The application's version. Versions must match for packet to be accepted.
     */
    public static final short VERSION = 0;

    /**
     * In addition to the IP header and UDP header, each packet also contains a 4-byte message header containing 6
     * constant bytes and 2 version bytes. This format should never be changed for compatibility reasons!
     */
    public static final byte[] MESSAGE_HEADER = { 'S', 'O', 'C', 'h', 'a', 't', VERSION & 0xff, (VERSION >> 8) & 0xff };

    /**
     * Limit the size of messages to this number of bytes.
     */
    public static final short MAX_MESSAGE_LENGTH = 1024;

    public static final String AUTH_SUCCESS = "Authentication successful.";

    public static final String AUTH_FAIL = "Invalid username or password";

    /**
     * The type of message we have received. The ordinal is used as the first byte of the message to identify the
     * message type within a UDP packet's payload.
     */
    public enum MessageType {
        UNKNOWN(0),

        /* BEGIN client-server authentication */
        CS_AUTH1(10), // C1 -> S: {Username, R, C1Sym}s
        CS_AUTH2(11), // C1Sym{R, salt, n}
        CS_AUTH3(12), // C1Sym{hash^n-1(P|salt)}
        CS_AUTH4(13), // C1Sym{ok}

        /* BEGIN server commands */
        CMD_LIST(20), // list users
        CMD_LIST_RESPONSE(21), // list response
        // CMD_LOGOUT(22), // logout from server/user

        /* BEGIN client-client authentication */
        CC_AUTH1(30), // C1 -> S: C1Sym{Username(C2), R1}
        CC_AUTH2(31), // S -> C1: C1Sym{IP(C2), R1}
        CC_AUTH3(32), // C1 -> C2: Username(C1), IP(C1)
        CC_AUTH4(33), // C2 -> C1: C2Sym{Username(C1), N’C2}
        CC_AUTH5(34), // C1 -> S: C2Sym{Username(C1), Username(C2), NC1},
                      // {Username(C1), N’C2}
        CC_AUTH6(35), // S -> C1: C1Sym{NC1, K12, Username(C2), C2Sym{K12,
                      // Username(C1), N’C2}}
        CC_AUTH7(36), // C1 -> C2: C2Sym{K12, Username(C1)}
        CC_AUTH8(37), // C2 -> C1: K12{NC2}
        CC_AUTH9(38), // C1 -> C2: K12{NC2-1}
        CC_MESSAGE(39); // K12{message}

        private final byte id;

        private MessageType(int id) {
            // takes in int to avoid casting in declarations here
            this.id = (byte) id;
        }

        public byte getId() {
            return id;
        }

        public static MessageType fromId(byte id) {
            for (int i = 0; i < values().length; ++i) {
                if (values()[i].id == id) {
                    return values()[i];
                }
            }
            return UNKNOWN;
        }

    }

}
