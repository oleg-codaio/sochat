package com.sochat.shared;

/**
 * Exception class pertaining to SOChat-specific exceptions.
 */
public class SoChatException extends Exception {

    private static final long serialVersionUID = 0;

    public SoChatException(String details) {
        super(details);
    }
}
