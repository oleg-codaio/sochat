package com.sochat.shared;

public final class Constants {

    /**
     * The application's version. Versions must match for packet to be accepted.
     */
    public static final short VERSION = 0;

    /**
     * In addition to the IP header and UDP header, each packet also contains a
     * 4-byte message header containing 6 constant bytes and 2 version bytes.
     * This format should never be changed for compatibility reasons!
     */
    public static final byte[] MESSAGE_HEADER = { 'S', 'O', 'C', 'h', 'a', 't', VERSION & 0xff, (VERSION >> 8) & 0xff };

    /**
     * Limit the size of messages to this number of bytes.
     */
    public static final short MAX_MESSAGE_LENGTH = 1024;

    /**
     * The type of message we have received. The ordinal is used as the first
     * byte of the message to identify the message type within a UDP packet's
     * payload.
     */
    public enum MessageType {
        CS_AUTH1, // C -> S 
        MESSAGE, INCOMING
    }

}
