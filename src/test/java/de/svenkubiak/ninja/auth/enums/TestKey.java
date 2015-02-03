package de.svenkubiak.ninja.auth.enums;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

/**
 * 
 * @author svenkubiak
 *
 */
public class TestKey {
    
    @Test
    public void TestValues() {
        assertEquals("auth.cookie.name", Key.AUTH_COOKIE_NAME.get());
        assertEquals("ninja-authentication", Key.DEFAULT_AUTH_COOKIE_NAME.get());
        assertEquals("auth.redirect.url", Key.AUTH_REDIRECT_URL.get());
        assertEquals("application.secret", Key.APPLICATION_SECRET.get());
        assertEquals("authenticateduser", Key.AUTHENTICATED_USER.get());
    }
}