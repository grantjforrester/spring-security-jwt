package com.github.grantjforrester.spring.security.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

/**
 * A Spring AuthenticationFilter that assumes a user has been pre-authenticated by a third party and the details
 * of the service user are present in a JWT included in the request.
 *
 * The JWT is located in the request using a given {@link JWTProvider}.  Once located the JWT is translated
 * into a Spring security principal using a given {@link JWTAuthenticationManager}.  The security principal is then
 * made available into the Spring Security Architecture and filter chain processing continues.
 *
 * If no JWT is found in the request or the JWT was not valid then the request is not authenticated and
 * filter chain processing continues.
 */
public class JWTAuthenticationFilter extends AbstractPreAuthenticatedProcessingFilter {

    private static final Logger LOG = LoggerFactory.getLogger(JWTAuthenticationFilter.class);

    private JWTProvider jwtProvider;
    private JWTAuthenticationManager authenticationManager;

    public void setJwtProvider(JWTProvider jwtProvider) {
        LOG.trace("Parameters: {}", jwtProvider);
        this.jwtProvider = jwtProvider;
        LOG.trace("Returning: none");
    }


    @Override
    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        LOG.trace("Parameters: {}", authenticationManager);
        this.authenticationManager = (JWTAuthenticationManager) authenticationManager;
        super.setAuthenticationManager(authenticationManager);
        LOG.trace("Returning: none");
    }

    /**
     * Get the principal from the given request.
     * Uses the {@link JWTProvider} to locate the JWT and the {@link JWTAuthenticationManager} to return a
     * Spring principal
     * @param request the request
     * @return a Spring principal, or null if no JWT was found in the request or the JWT was not valid.
     */
    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        LOG.trace("Parameters: {}", request);
        Object principal = null;
        Optional<String> jwt = jwtProvider.getJWTFromRequest(request);
        if (jwt.isPresent()) {
            principal = authenticationManager.getPrincipalFrom(jwt.get()).orElse(null);
        }
        LOG.trace("Returning: {}", principal);

        return principal;
    }

    /**
     * Get the credentials from the given request.
     * Returns the JWT from the {@link JWTProvider} as the credentials.
     * @param request the request
     * @return the credentials, or null if no JWT was found in the request.
     */
    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        LOG.trace("Parameters: {}", request);
        String token = jwtProvider.getJWTFromRequest(request).orElse(null);
        LOG.trace("Returning: {}", token);

        return token;
    }
}
