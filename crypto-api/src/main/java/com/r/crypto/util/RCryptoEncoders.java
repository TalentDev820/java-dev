package com.r.crypto.util;

import java.util.Base64;

/**
 * These are the same encoders rn-keytool uses.
 */
public class RCryptoEncoders {
    public static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    public static final Base64.Decoder DECODER = Base64.getUrlDecoder();
}
