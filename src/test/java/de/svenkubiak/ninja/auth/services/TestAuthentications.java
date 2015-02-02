package de.svenkubiak.ninja.auth.services;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;
import ninja.Context;
import ninja.Cookie;
import ninja.NinjaTest;
import ninja.session.Session;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import de.svenkubiak.ninja.auth.enums.Key;

/**
 * 
 * @author svenkubiak
 *
 */
public class TestAuthentications extends NinjaTest {
    private static final String USERNAME = "username";
    private Authentications authentications;
    private Context context = Mockito.mock(Context.class);
    
    @Before
    public void init() {
        authentications = getInjector().getInstance(Authentications.class);
        Session session = getInjector().getInstance(Session.class);
        
        Cookie cookie = Cookie.builder("testcookie", "foo")
            .setSecure(true)
            .setHttpOnly(true).build();
        
        when(context.getSession()).thenReturn(session);
        when(context.getCookie(Key.AUTH_COOKIE_NAME.getValue())).thenReturn(cookie);
    }
    
    @Test
    public void testGetHashedPassword() {
        String password = "123password";
        
        assertNotNull(authentications.getHashedPassword(password));
    }
    
    @Test
    public void testValidCheckpassword() {
        String password = "123password";
        String hash = authentications.getHashedPassword(password);
        
        assertTrue(authentications.authenticate(password, hash));
    }
    
    @Test
    public void testInValidCheckpassword() {
        String password = "123password";
        assertFalse(authentications.authenticate(password, "foo"));
    }
    
    @Test
    public void testLoginLogout() {
        assertNull(USERNAME, authentications.getAuthenticatedUser(context));
        authentications.login(context, USERNAME, false);
        assertEquals(USERNAME, authentications.getAuthenticatedUser(context));
        authentications.logout(context);
        assertNull(USERNAME, authentications.getAuthenticatedUser(context));
    }
}