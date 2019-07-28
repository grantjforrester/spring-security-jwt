package com.github.grantjforrester.spring.security.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;
import static org.springframework.http.HttpHeaders.WWW_AUTHENTICATE;

/**
 * Sends a 401 response when service user is not authenticated.
 * The response includes the response header <code>WWW-Authenticate: Bearer</code>.
 */
public class StatusCode401AuthenticationEntrypoint implements AuthenticationEntryPoint {

    private static final Logger LOG = LoggerFactory.getLogger(StatusCode401AuthenticationEntrypoint.class);
    private static final String AUTH_SCHEME = "Bearer";

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
            throws IOException {
        LOG.trace("Parameters: {}, {}, {}", request, response, exception);
        response.setHeader(WWW_AUTHENTICATE, AUTH_SCHEME);
        response.sendError(SC_UNAUTHORIZED, exception.getMessage());
        LOG.trace("Returning: none");
    }
}
