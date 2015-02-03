package de.svenkubiak.ninja.auth.services;

import java.util.Date;

import ninja.Context;
import ninja.Cookie;
import ninja.utils.NinjaProperties;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.mindrot.jbcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Preconditions;
import com.google.inject.Inject;
import com.google.inject.Singleton;

import de.svenkubiak.ninja.auth.enums.Key;

/**
 * 
 * @author svenkubiak
 *
 */
@Singleton
public class Authentications {
    private static final Logger LOG = LoggerFactory.getLogger(Authentications.class); 
    private static final String SEPARATOR = "##";
    private static final int COOKIE_VARS = 3;
    private static final int TWO_WEEKS_SECONDS = 1209600;
    private static final int TWO_WEEKS_MILLISECONDS = 1209600000;
    private static final int LOG_ROUNDS = 12;
    
    @Inject
    private NinjaProperties ninjaProperties;
    
    /**
     * Retrieves the current authenticated user from the context. Lookup is
     * first done via session, then via cookie. If a user is not found in the
     * session but in the cookie, the username will be added to the session
     * for next lookup.
     * 
     * @param context The current context
     * 
     * @return The username of the authenticated user or null if none is found
     */
    public String getAuthenticatedUser(Context context) {
        Preconditions.checkNotNull(context, "Valid context is required for getAuthenticatedUser");
        
        String username = getUsernameFromSession(context);
        if (StringUtils.isNotBlank(username)) {
            return username;
        }
        
        username = getUsernameFromCookie(context);
        if (StringUtils.isNotBlank(username)) {
            context.getSession().put(Key.AUTHENTICATED_USER.get(), username);
            return username;
        }
        
        return null;
    }
    
    /**
     * Generates a hash value for a given password using BCrypt
     * 
     * @param password The password to hash
     * 
     * @return The hashed value 
     */
    public String getHashedPassword(String password) {
        Preconditions.checkNotNull(password, "Password is required for getHashedPassword");
        
        return BCrypt.hashpw(password, BCrypt.gensalt(LOG_ROUNDS));
    }
    
    /**
     * Checks a clear text password against a previously hashed BCrypt one
     * 
     * @param password The cleartext password
     * @param hash The with {@link #getHashedPassword(String)} created hash value
     * 
     * @return True if the password matches, false otherwise
     */
    public boolean authenticate(String password, String hash) {
        Preconditions.checkNotNull(password, "Password is required for authenticate");
        Preconditions.checkNotNull(password, "Hashed password is required for authenticate");
        
        boolean authenticated = false;
        try {
            authenticated = BCrypt.checkpw(password, hash);
        } catch (IllegalArgumentException e) {
            LOG.error("Failed to check password against hash", e);
        }
        
        return authenticated;
    }
    
    /**
     * Performs a logout in the current context, remove the user session and cookie
     * 
     * @param context The current context
     */
    public void logout(Context context) {
        Preconditions.checkNotNull(context, "Valid context is required for logout");
        
        //TODO use new unset cookie function context.unsetCookie(coookie)
        if (context.hasCookie(getCookieName())) {
            Cookie.builder(context.getCookie(getCookieName())).setMaxAge(0); 
        }
        
        context.getSession().clear();
    }
    
    /**
     * Return the name of the authentication cookie
     * 
     * @return Name of the authentication cookie
     */
    private String getCookieName() {
        String prefix = ninjaProperties.get("application.cookie.prefix") + "-";
        return prefix + ninjaProperties.getWithDefault(Key.AUTH_COOKIE_NAME.get(), Key.DEFAULT_AUTH_COOKIE_NAME.get());
    }
    
    /**
     * Performs a login by putting the username in the current conext sesssion. If remember
     * is passed as true, a cookie will be store as well for keeping the user logged in
     * if the browser is closed.
     * 
     * IMPORTANT: Only call this method if you are certain that the user is authenticated!
     * 
     * @param context The current context
     * @param username The username to login
     * @param remember True if the username should stay login after the browser is closed
     */
    public void login(Context context, String username, boolean remember) {
        Preconditions.checkNotNull(context, "Valid context is required for login");
        Preconditions.checkNotNull(username, "Username is required for login");
        
        context.getSession().put(Key.AUTHENTICATED_USER.get(), username);
        if (remember) {
            setCookie(username, context);
        }
    }
    
    /**
     * Creates a cookie storing the username as cleartext and as a hased value.
     * This function is used, when the user wants to stay logged in, even if the
     * browser is closed.
     * 
     * @param username The username to create the cookie
     */
    private void setCookie(String username, Context context) {
        Preconditions.checkNotNull(username, "Username is required for setCookie");
        Preconditions.checkNotNull(context, "Context is required for setCookie");
        
        long timestamp = new Date().getTime();
        StringBuilder buffer = new StringBuilder();
        buffer.append(getSignature(username, timestamp))
            .append(SEPARATOR)
            .append(username)
            .append(SEPARATOR)
            .append(timestamp);
        
        Cookie.builder(getCookieName(), buffer.toString())
            .setSecure(true)
            .setHttpOnly(true)
            .setMaxAge(ninjaProperties.getIntegerWithDefault(Key.AUTH_COOKIE_EXPIRES.get(), TWO_WEEKS_SECONDS))
            .build();
        
        //TODO Add cookie to context!
    }
    
    /**
     * Creates a signature for a given username by hashing it with the ninja
     * application secret
     * 
     * @param username The username to create the signature
     * 
     * @return The signature
     */
    private String getSignature(String username, long timestamp) {
        Preconditions.checkNotNull(username, "Username is required for getSignature");
        Preconditions.checkNotNull(timestamp, "Timestamp is required for getSignature");
        
        return DigestUtils.sha512Hex(username + timestamp + ninjaProperties.get(Key.APPLICATION_SECRET.get()));
    }
    
    /**
     * Checks if a username is present in the current context in a cookie
     * 
     * @param context The current context
     * @return The username or null if none is present
     */
    private String getUsernameFromCookie(Context context) {
        Preconditions.checkNotNull(context, "Valid context is required for getUsernameFromCookie");
        
        Cookie cookie = context.getCookie(getCookieName());
        if (cookie != null && StringUtils.isNotBlank(cookie.getValue())) {
            String [] cookieValue = cookie.getValue().split(SEPARATOR);
            if (cookieValue.length == COOKIE_VARS) {
                String sign = cookieValue[0];
                String username = cookieValue[1];
                long timestamp = Long.parseLong(cookieValue[2]);
                
                if (getSignature(username, timestamp).equals(sign) && ((timestamp + TWO_WEEKS_MILLISECONDS) > new Date().getTime())) {
                    return username;
                }
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
        Preconditions.checkNotNull(context, "Valid context is required for getUsernameFromSession");

        return context.getSession().get(Key.AUTHENTICATED_USER.get());
    }
}