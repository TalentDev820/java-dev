package com.r.crypto.api;

import com.r.crypto.exception.RCryptoException;
import org.testng.annotations.Test;

import static com.r.crypto.util.RCryptoEncoders.DECODER;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

public class CryptotextTest {
    /** Parsing both null header and data means the cryptotext itself is null */
    @Test
    public void parse_null() {
        assertNull(Cryptotext.parse(null, null));
    }

    /** Header can't be null (unless data also null) */
    @Test(expectedExceptions = RCryptoException.class)
    public void parse_nullHeader() {
        Cryptotext.parse(null, new byte[] {});
    }

    /** Invalid header format, at a minimum must be inside curly braces */
    @Test(expectedExceptions = RCryptoException.class)
    public void parse_invalidHeader() {
        Cryptotext.parse("abc", null);
    }

    /** Header argument must be only the header, not a full Cryptotext.encode() result */
    @Test(expectedExceptions = RCryptoException.class)
    public void parse_invalidHeaderFullCryptotext() {
        Cryptotext cryptotext = new Cryptotext("aes", new byte[] { 1, 2, 3 });
        Cryptotext.parse(cryptotext.encode(), null);
    }

    @Test
    public void parse_nullData() {
        Cryptotext cryptotext = Cryptotext.parse("{aes}", null);
        assertEquals(cryptotext.header(), "{aes}");
        assertNull(cryptotext.getData());
    }

    @Test
    public void parse() {
        testParse("{aes}abcd");
        testParse("{aes[gcm]}abcd");
        testParse("{aes[gcm,128,96]}abcd");
        testParse("{aes:key=foobar#1}abcd");
        testParse("{aes[gcm]:key=foobar#1}abcd");
        testParse("{aes[gcm,128,96]:key=foobar#1}abcd");

        Cryptotext cryptotext = Cryptotext.parse("{aes[gcm]}", DECODER.decode("abcd"));
        assertNotNull(cryptotext);
        assertEquals("{aes[gcm]}abcd", cryptotext.encode());
    }

    private void testParse(String s) {
        assertEquals(s, Cryptotext.parse(s).encode());
    }
}
