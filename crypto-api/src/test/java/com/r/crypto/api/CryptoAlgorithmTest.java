package com.r.crypto.api;

import org.testng.annotations.Test;

import java.util.regex.Matcher;

import static com.r.crypto.api.CryptoAlgorithm.CRYPTO_ALGORITHM_PATTERN;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class CryptoAlgorithmTest {
    @Test
    public void parse() {
        assertTrue(checkParse("cipher:aes"));
        assertTrue(checkParse("cipher:aes[gcm,128,96]"));
    }

    @Test
    public void matches() {
        assertTrue(new CryptoAlgorithm("aes").matches("aes[gcm,128,96]", "aes[cbc]"));
        assertTrue(new CryptoAlgorithm("aes[cbc]").matches("aes[gcm,128,96]", "aes[cbc]"));
        assertTrue(checkMatches("aes[gcm,128,96]", "aes"));
        assertTrue(checkMatches("aes[gcm,128,96]", "aes[gcm]"));
        assertFalse(checkMatches("aes[gcm,128,96]", "aes[cbc]"));
        assertFalse(checkMatches("aes[gcm,128,96]", "aes[gcm,96]"));
        assertTrue(checkMatches("aes[gcm,128,96]", "aes[gcm,128,96]"));
        assertFalse(checkMatches("aes[gcm,128,96]", "aes[gcm,128,96,foo]"));
    }

    private static boolean checkParse(String s) {
        Matcher matcher = CRYPTO_ALGORITHM_PATTERN.matcher(s);
        if (matcher.matches()) {
            CryptoAlgorithm algorithm = CryptoAlgorithm.parse(s);
            System.out.printf("%25s %10s %20s%n",
                    s,
                    algorithm.getAlgorithmName(),
                    algorithm.getParameters());
            return true;
        } else {
            System.out.printf("%25s: did not match%n", s);
            return false;
        }
    }

    private static boolean checkMatches(String s1, String s2) {
        CryptoAlgorithm a1 = CryptoAlgorithm.parse("cipher:" + s1);
        CryptoAlgorithm a2 = CryptoAlgorithm.parse("cipher:" + s2);
        System.out.printf("%20s %20s: %s%n", a1.encode(), a2.encode(), a2.matches(a1));
        return a2.matches(a1);
    }
}
