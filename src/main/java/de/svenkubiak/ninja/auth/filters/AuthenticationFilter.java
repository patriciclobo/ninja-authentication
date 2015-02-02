package de.svenkubiak.ninja.auth.filters;

import ninja.Context;
import ninja.Filter;
import ninja.FilterChain;
import ninja.Result;
import ninja.Results;
import ninja.i18n.Messages;
import ninja.utils.Message;
import ninja.utils.NinjaConstant;
import ninja.utils.NinjaProperties;

import org.apache.commons.lang3.StringUtils;

import com.google.common.base.Optional;
import com.google.inject.Inject;

import de.svenkubiak.ninja.auth.enums.Key;
import de.svenkubiak.ninja.auth.services.Authentications;

/**
 * 
 * @author svenkubiak
 *
 */
public class AuthenticationFilter implements Filter {
    
    @Inject
    private NinjaProperties ninjaProperties;
    
    @Inject
    private Authentications authenticationService;
    
    @Inject
    private Messages messages;
    
    @Override
    public Result filter(FilterChain filterChain, Context context) {
        if (StringUtils.isBlank(authenticationService.getAuthenticatedUser(context))) {
            String redirect = ninjaProperties.get(Key.AUTH_REDIRECT_URL.getValue());
            return (StringUtils.isBlank(redirect)) ? forbidden(context) : Results.redirect(redirect);
        }
        
        return filterChain.next(context);
    }
    
    private Result forbidden(Context context) {
        String messageI18n 
            = messages.getWithDefault(
                NinjaConstant.I18N_NINJA_SYSTEM_FORBIDDEN_REQUEST_TEXT_KEY,
                NinjaConstant.I18N_NINJA_SYSTEM_FORBIDDEN_REQUEST_TEXT_DEFAULT,
                context,
                Optional.<Result>absent());

        return Results.forbidden()
                      .supportedContentTypes(Result.TEXT_HTML, Result.APPLICATION_JSON, Result.APPLICATION_XML)
                      .fallbackContentType(Result.TEXT_HTML)
                      .render(new Message(messageI18n))
                      .template(NinjaConstant.LOCATION_VIEW_FTL_HTML_FORBIDDEN);
    }
}