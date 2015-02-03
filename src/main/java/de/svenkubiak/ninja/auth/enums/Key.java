package de.svenkubiak.ninja.auth.enums;

/**
 * 
 * @author svenkubiak
 *
 */
public enum Key {
    AUTH_COOKIE_NAME("auth.cookie.name"),
    AUTH_COOKIE_EXPIRES("auth.cookie.expires"),
    AUTH_REDIRECT_URL("auth.redirect.url"),
    APPLICATION_SECRET("application.secret"),
    AUTHENTICATED_USER("authenticateduser"),
    DEFAULT_AUTH_COOKIE_NAME("ninja-authentication");
    
    private final String value;

    Key (String value) {
        this.value = value;
    }

    public String get() {
        return this.value;
    }
}