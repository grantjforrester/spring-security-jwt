package com.github.grantjforrester.spring.security.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

/**
 * A {@link JWTProvider} that looks for a token in an HTTP request header.
 *
 * The provider looks for a named header (by default {@value #DEFAULT_AUTHORIZATION_HEADER}) in the request
 * and if found expects the header to be in the format:
 * <pre>
 *     HEADER : &lt;AUTHENTICATION_SCHEME&gt; &lt;TOKEN_STRING&gt;
 * </pre>
 * The authentication scheme is configurable. The default expected authentication scheme is
 * {@value #DEFAULT_UTHORIZATION_SCHEME}.
 */
public class HeaderJWTProvider implements JWTProvider {

    private static final Logger LOG = LoggerFactory.getLogger(HeaderJWTProvider.class);
    public static final String DEFAULT_AUTHORIZATION_HEADER = "Authorization";
    public static final String DEFAULT_UTHORIZATION_SCHEME = "Bearer";
    private final String headerName;
    private final String authScheme;

    /**
     * Create a HeaderJWTProvider that expects a JWT in a request header named {@value #DEFAULT_AUTHORIZATION_HEADER}.
     * The authentication scheme of the header value is expected to be {@value #DEFAULT_UTHORIZATION_SCHEME}.
     */
    public HeaderJWTProvider() {
        this(DEFAULT_AUTHORIZATION_HEADER, DEFAULT_UTHORIZATION_SCHEME);
    }

    /**
     * Create a HeaderJWTProvider for a header with the given name and authentication scheme.
     * @param headerName the name of the request header holding the JWT.
     * @param authScheme the expected authentication scheme.
     */
    public HeaderJWTProvider(String headerName, String authScheme) {
        LOG.trace("Parameters: none");
        this.headerName = headerName;
        this.authScheme = authScheme;
        LOG.trace("Returning: none");
    }

    /**
     * {@inheritDoc}
     *
     * Looks for the JWT in a named header with the given authentication scheme.
     */
    @Override
    public Optional<String> getJWTFromRequest(HttpServletRequest request) {
        LOG.trace("Parameters: none");
        Optional<String> jwt = Optional.empty();
        String authorizationHeader = request.getHeader(headerName);
        if (authorizationHeader != null && authorizationHeader.startsWith(authScheme)) {
            String jwtString = authorizationHeader.substring(authScheme.length()).trim();
            if (jwtString.length() > 0) {
                jwt = Optional.of(jwtString);
            }
        }
        if(!jwt.isPresent()) {
            LOG.debug("No JWT found in header '{}' with auth scheme '{}'", headerName, authScheme);
        }
        LOG.trace("Returning: {}", jwt);

        return jwt;
    }

}
