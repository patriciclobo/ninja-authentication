package de.svenkubiak.ninja.auth.services;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.UUID;

import ninja.Context;
import ninja.Cookie;
import ninja.utils.NinjaProperties;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Preconditions;
import com.google.inject.Inject;

import de.svenkubiak.ninja.auth.enums.Key;

/**
 * 
 * @author svenkubiak
 *
 */
public class AuthenticationService {
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationService.class);
    private static final int MAX_LENGTH = 128;
    
    @Inject
    private NinjaProperties ninjaProperties;
    
    /**
     * Retrieves the current authenticated user from the context. Lookup is
     * first done via session, then via cookie.
     * 
     * @param context The current context
     * 
     * @return The username of the authenticated user
     */
    public String getAuthenticatedUser(Context context) {
        Preconditions.checkNotNull(context, "Valid context is required");
        
        String username = getUsernameFromSession(context);
        if (StringUtils.isNotBlank(username)) {
            return username;
        }
        
        username = getUsernameFromCookie(context);
        if (StringUtils.isNotBlank(username)) {
            return username;
        }
        
        return null;
    }

    /**
     * Convenient function to check if a given user is authenticated.
     * 
     * @param context The current context
     * @param username The username to check
     * 
     * @return True if the user is authenticated, false otherwise
     */
    public boolean isAuthenticated(Context context, String username) {
        Preconditions.checkNotNull(context, "Valid context is required to check if a given username is authenticated");
        Preconditions.checkNotNull(username, "Username is required to check if a given username is authenticated");
        
        return username.equals(getAuthenticatedUser(context));
    }
    
    /**
     * Generates a SHA2(SHA512) hash value for the given password and salt
     * 
     * @param password The password to hash
     * @param salt The salt to use
     * 
     * @return The hashed value 
     */
    public String getHashedPassword(String password, String salt) {
        Preconditions.checkNotNull(password, "Password is required for hashing a password");
        Preconditions.checkNotNull(salt, "Salt is required for hashing a password");
        
        return DigestUtils.sha512Hex(password + salt);
    }
    
    /**
     * Performs a logout in the current context, remove the user session and cookie.
     * 
     * @param context The current context
     */
    public void logout(Context context) {
        Preconditions.checkNotNull(context, "Valid context is required");
        
        Cookie.builder(context.getCookie(Key.AUTH_COOKIE_NAME.getValue())).setMaxAge(0);
        context.getSession().clear();
    }
    
    /**
     * Convenient function for creating a SecureRandom based salt
     * 
     * @return The salt
     */
    public String getSalt() {
        SecureRandom secureRandom;
        byte[] bytes = new byte[MAX_LENGTH];
        try {
            secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.nextBytes(bytes); 
        } catch (NoSuchAlgorithmException e) {
            LOG.error("Failed to generate salt", e);
        }
        
        return (bytes == null) ? UUID.randomUUID().toString() : Base64.encodeBase64String(bytes);
    }
    
    /**
     * Performs a login by putting the username in the current conext sesssion. If remember
     * is passed as true, a cookie will be store as well for keeping the user logged in
     * even if the browser is closed.
     * 
     * @param context The current context
     * @param username The username to login
     * @param remember True if the username should stay login after the browser is close, false otherwise
     */
    public void login(Context context, String username, boolean remember) {
        Preconditions.checkNotNull(context, "Valid context is required for login");
        Preconditions.checkNotNull(username, "Username is required for login");
        
        context.getSession().put(Key.AUTHENTICATED_USER.getValue(), username);
        if (remember) {
            setCookie(username);
        }
    }
    
    /**
     * Creates a cookie storing the cleartext and signed username. This function is used, when
     * the user wants to stay logged in, even if the browser is close.
     * 
     * @param username The username to create the cookie
     */
    private void setCookie(String username) {
        Cookie.builder(ninjaProperties.get(Key.AUTH_COOKIE_NAME.getValue()), getSignature(username))
            .setSecure(true)
            .setHttpOnly(true)
            .build();
    }
    
    /**
     * Creates a signature for for a given username by hashin it with the ninja
     * application secret
     * 
     * @param username The username to create the signature
     * 
     * @return The signature
     */
    private String getSignature(String username) {
        Preconditions.checkNotNull(username, "Username is required for creating signature");
        
        return DigestUtils.sha512Hex(username + ninjaProperties.get(Key.APPLICATION_SECRET.getValue()));
    }
    
    /**
     * Checks if a username is present in the current context in a cookie
     * 
     * @param context The current context
     * @return The username or null if none is present
     */
    private String getUsernameFromCookie(Context context) {
        Preconditions.checkNotNull(context, "Valid context is required for getting username from Cookie");
        
        Cookie cookie = context.getCookie(ninjaProperties.get(Key.AUTH_COOKIE_NAME.getValue()));
        if (cookie != null && StringUtils.isNotBlank(cookie.getValue()) && cookie.getValue().indexOf("-") > 0) {
            final String sign = cookie.getValue().substring(0, cookie.getValue().indexOf("-"));
            final String username = cookie.getValue().substring(cookie.getValue().indexOf("-") + 1);

            if (StringUtils.isNotBlank(sign) && StringUtils.isNotBlank(username) && sign.equals(getSignature(username))) {
                return username;
            }
        }
        
        return null;
    }
    
    /**
     * Checks if a username is present in the current context in a session
     * 
     * @param context The current context
     * @return The username or null if none is present
     */
    private String getUsernameFromSession(Context context) {
        Preconditions.checkNotNull(context, "Valid context is required for getting username from session");

        return context.getSession().get(Key.AUTHENTICATED_USER.getValue());
    }
}