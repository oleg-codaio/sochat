package com.sochat.shared;

public final class Constants {

    /**
     * The application's version. Versions must match for packet to be accepted.
     */
    public static final short VERSION = 0;

    /**
     * In addition to the IP header and UDP header, each packet also contains a
     * 4-byte message header containing 2 constant bytes and 2 version bytes.
     * This should never be changed!
     */
    public static final byte[] MESSAGE_HEADER = { 'O', 'c', VERSION & 0xff, (VERSION >> 8) & 0xff };

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
        GREETING, MESSAGE, INCOMING
    }

}
