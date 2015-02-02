package de.svenkubiak.ninja.auth.services;

import ninja.Context;
import ninja.NinjaTest;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

public class TestAuthenticationsValidations extends NinjaTest {
    private Authentications authentications;
    private Context context = Mockito.mock(Context.class);
    
    @Before
    public void init() {
        authentications = getInjector().getInstance(Authentications.class);
    }

    @Test(expected=NullPointerException.class)
    public void testGetAuthenticatedUser() {
        authentications.getAuthenticatedUser(null);
    }
    
    @Test(expected=NullPointerException.class)
    public void testIsAuthenticated() {
        authentications.isAuthenticated(null, null);
    }
    
    @Test(expected=NullPointerException.class)
    public void testIsAuthenticated2() {
        authentications.isAuthenticated(context, null);
    }
    
    @Test(expected=NullPointerException.class)
    public void testIsAuthenticated3() {
        authentications.isAuthenticated(null, "foo");
    }
    
    @Test(expected=NullPointerException.class)
    public void testGetHashedPassword() {
        authentications.getHashedPassword(null);
    }
    
    @Test(expected=NullPointerException.class)
    public void testAuthenticate() {
        authentications.authenticate(null, null);
    }
    
    @Test(expected=NullPointerException.class)
    public void testAuthenticate2() {
        authentications.authenticate("foo", null);
    }
    
    @Test(expected=NullPointerException.class)
    public void testAuthenticate3() {
        authentications.authenticate(null, "foo");
    }
    
    @Test(expected=NullPointerException.class)
    public void testLogout() {
        authentications.logout(null);
    }
    
    @Test(expected=NullPointerException.class)
    public void testLogin() {
        authentications.login(null, null, false);
    }
    
    @Test(expected=NullPointerException.class)
    public void testLogin2() {
        authentications.login(context, null, false);
    }
    
    @Test(expected=NullPointerException.class)
    public void testLogin3() {
        authentications.login(null, "foo", false);
    }
}