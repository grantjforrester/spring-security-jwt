package com.github.grantjforrester.springsecurityjwt;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;

/**
 * Sends a 401 response when service user is not authenticated.
 * The response includes the response header <code>WWW-Authenticate: Bearer</code>.
 */
public class StatusCode401AuthenticationEntrypoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
            throws IOException {
        response.setHeader("WWW-Authenticate", "Bearer");
        response.sendError(SC_UNAUTHORIZED, exception.getMessage());
    }
}
