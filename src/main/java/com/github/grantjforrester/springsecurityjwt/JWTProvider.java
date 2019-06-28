package com.github.grantjforrester.springsecurityjwt;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

/**
 * Strategy to extract a JWT from an HTTP request.
 */
public interface JWTProvider {

    /**
     * Extracts a JWT from an HTTP request.
     * @param request the current request.
     * @return an optional JWT as a string if token was found.
     */
    Optional<String> getJWTFromRequest(HttpServletRequest request);
}
