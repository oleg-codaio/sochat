package com.sochat.shared;

public class Utils {

    /**
     * Returns whether the two sub-arrays are equal.
     * 
     * @param a1
     *            The first array
     * @param o1
     *            The offset for the first array
     * @param a2
     *            The second array
     * @param o2
     *            The offset for the second array
     * @param len
     *            How many elements to compare
     * @return
     */
    public static final boolean arrayEquals(byte[] a1, int o1, byte[] a2, int o2, int len) {
        for (int i = 0; i < len; ++i) {
            if (a1[o1 + i] != a2[o2 + i])
                return false;
        }
        return true;
    }

}
