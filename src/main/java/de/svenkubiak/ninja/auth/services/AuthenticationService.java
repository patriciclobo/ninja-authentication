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
    private static final int MAX_LENGTH = 512;

    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationService.class);
    
    @Inject
    private NinjaProperties ninjaProperties;
    
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
    
    public String getHashedPassword(String password, String salt) {
        Preconditions.checkNotNull(password, "Password is required for hashing a password");
        Preconditions.checkNotNull(salt, "Salt is required for hashing a password");
        
        return DigestUtils.sha512Hex(password + salt);
    }
    
    public void logout(Context context) {
        Preconditions.checkNotNull(context, "Valid context is required");
        
        Cookie.builder(context.getCookie(Key.AUTH_COOKIE_NAME.getValue())).setMaxAge(0);
        context.getSession().clear();
    }
    
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
    
    public void login(Context context, String username, boolean remember) {
        Preconditions.checkNotNull(context, "Valid context is required for login");
        Preconditions.checkNotNull(username, "Username is required for login");
        
        context.getSession().put(Key.AUTHENTICATED_USER.getValue(), username);
        if (remember) {
            setCookie(username);
        }
    }
    
    private void setCookie(String username) {
        Cookie.builder(ninjaProperties.get(Key.AUTH_COOKIE_NAME.getValue()), getSignature(username))
            .setSecure(true)
            .setHttpOnly(true)
            .build();
    }
    
    private String getSignature(String username) {
        Preconditions.checkNotNull(username, "Username is required for creating signature");
        
        return DigestUtils.sha512Hex(username + ninjaProperties.get(Key.APPLICATION_SECRET.getValue()));
    }
    
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
    
    private String getUsernameFromSession(Context context) {
        Preconditions.checkNotNull(context, "Valid context is required for getting username from session");
        
        if (context.getSession() != null) {
            return context.getSession().get(Key.AUTHENTICATED_USER.getValue());
        }
        
        return null;
    }
}