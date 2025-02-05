package com.r.crypto.encryption.hibernate;

import org.testng.annotations.Test;

import jakarta.persistence.CascadeType;
import java.util.HashSet;
import java.util.Set;

import static com.r.crypto.encryption.hibernate.EntityCrawler.shouldCascade;
import static com.r.crypto.util.Util.set;
import static java.util.Collections.singleton;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class EntityCrawlerTest {
    private static final Set<CascadeType> EMPTY = new HashSet<>();

    @Test
    public void cascade() {
        // Field has no cascades, so don't cascade
        assertFalse(shouldCascade(EMPTY, EMPTY));
        assertFalse(shouldCascade(set(CascadeType.ALL), EMPTY));

        // Unless we explicitly ask to cascade "null", which means cascade anyway
        assertTrue(shouldCascade(singleton(null), EMPTY));

        assertFalse(shouldCascade(set(CascadeType.ALL), set(CascadeType.PERSIST)));
    }
}