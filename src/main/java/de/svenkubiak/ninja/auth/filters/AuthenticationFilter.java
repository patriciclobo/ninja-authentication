package de.svenkubiak.ninja.auth.filters;

import ninja.Context;
import ninja.Filter;
import ninja.FilterChain;
import ninja.Result;
import ninja.Results;
import ninja.utils.NinjaProperties;

import org.apache.commons.lang3.StringUtils;

import com.google.inject.Inject;

import de.svenkubiak.ninja.auth.enums.Key;
import de.svenkubiak.ninja.auth.services.AuthenticationService;

/**
 * 
 * @author svenkubiak
 *
 */
public class AuthenticationFilter implements Filter {
    
    @Inject
    private NinjaProperties ninjaProperties;
    
    @Inject
    private AuthenticationService authenticationService;
    
    public Result filter(FilterChain filterChain, Context context) {
        if (StringUtils.isBlank(authenticationService.getAuthenticatedUser(context))) {
            String redirect = ninjaProperties.get(Key.AUTH_REDIRECT_URL.value());
            return (StringUtils.isBlank(redirect)) ? Results.forbidden() : Results.redirect(redirect);
        }
        
        return filterChain.next(context);
    }
}