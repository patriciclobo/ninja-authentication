package de.svenkubiak.ninja.auth.services;

import static org.junit.Assert.assertEquals;
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
public class TestAuthenticationService extends NinjaTest {
    private static final String USERNAME = "username";
    private static final String HASHED_PASSWORD = "80a9ecbc2909b95f71f8696b9c4d6e66b7015fa716bf30a19b3f83de20f5fea9a4925e35d48644affd703b115ff465b52ba50434464e7eaaaae7f38937c7ee51";
    private Authentications authenticationService;
    private Context context = Mockito.mock(Context.class);
    
    @Before
    public void init() {
        authenticationService = getInjector().getInstance(Authentications.class);
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
        String salt = "mysaltismypassword";
        
        assertEquals(HASHED_PASSWORD, authenticationService.getHashedPassword(password, salt));
    }
    
    @Test
    public void testGetSalt() {
        String salt = authenticationService.getSalt();
        
        assertNotNull(salt);
        assertTrue(salt.length() == 172);
    }
    
    @Test
    public void testLoginLogout() {
        assertNull(USERNAME, authenticationService.getAuthenticatedUser(context));
        authenticationService.login(context, USERNAME, false);
        assertEquals(USERNAME, authenticationService.getAuthenticatedUser(context));
        authenticationService.logout(context);
        assertNull(USERNAME, authenticationService.getAuthenticatedUser(context));
    }
}