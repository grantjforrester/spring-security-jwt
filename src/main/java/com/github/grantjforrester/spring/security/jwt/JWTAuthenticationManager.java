package com.github.grantjforrester.spring.security.jwt;

import org.springframework.security.authentication.AuthenticationManager;

import java.util.Optional;

/**
 * A Spring AuthenticationManager that uses a JSON Web Token to perform authentication.
 * Authentication will be based on verifying the authenticity of the JWT.
 */
public interface JWTAuthenticationManager extends AuthenticationManager {

    /**
     * Builds a Spring security principal from the given JWT.
     * @param jwt the JWT.
     * @return a Spring security principal, or <code>null</code> if the JWT was not valid.
     */
    Optional<Object> getPrincipalFrom(String jwt) ;


}
