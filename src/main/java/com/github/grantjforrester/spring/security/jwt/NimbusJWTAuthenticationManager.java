package com.github.grantjforrester.spring.security.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.text.ParseException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.util.Collections.emptySet;

/**
 * A JWTAuthenticationManager that uses the Nimbus JOSE + JWT library.
 */
public class NimbusJWTAuthenticationManager implements JWTAuthenticationManager {

    /**
     * The JWT claim that holds the service user roles.
     */
    public static final String ROLES_CLAIM = "roles";

    private static final Logger LOG = LoggerFactory.getLogger(NimbusJWTAuthenticationManager.class);

    private final DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();

    public NimbusJWTAuthenticationManager(JWKSetManager keyManager) {
        LOG.trace("Parameters: {}", keyManager);
        if (keyManager == null) {
            throw new NullPointerException("keyManager cannot be null");
        }
        processor.setJWSKeySelector(keyManager);
        LOG.trace("Returning: none");
    }

    /**
     * {@inheritDoc}
     *
     * The security principal name is set from the JWT 'subject' claims.
     * The security principal authorities are {@link Collections#emptySet()}.
     * If no 'subject' in the JWT or the JWT is invalid then returns an empty <code>Optional</code>.
     */
    @Override
    public Optional<Object> getPrincipalFrom(String jwt) {
        LOG.trace("Parameters: token={}", jwt);
        Optional<Object> principal = Optional.empty();
        Optional<String> subject = Optional.ofNullable(getSubject(jwt));
        if (!subject.isPresent())
            LOG.debug("Could not determine principal from JWT as no 'sub' claim present: {}", jwt);
        principal = subject.map(s -> buildPrincipal(s, emptySet()));
        LOG.trace("Returning: {}", principal);

        return principal;
    }

    /**
     * {@inheritDoc}
     *
     * This implementation authenticates the principal by verifying the JWT (from <code>Authentication.getCredentials()</code>)
     * The returned security principal name is set from the given Authentication object.
     * The authorities are set from the {@value #ROLES_CLAIM} claims in the JWT.
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        LOG.trace("Parameters: authentication={}", authentication);
        String token = (String) authentication.getCredentials();
        Collection<? extends GrantedAuthority> authorities = buildAuthorities(token);
        User principal = buildPrincipal(authentication.getName(), authorities);
        Authentication successfulAuthentication = new PreAuthenticatedAuthenticationToken(
                principal, authentication.getCredentials(), authorities);
        successfulAuthentication.setAuthenticated(true);
        LOG.trace("Returning: {}", successfulAuthentication);

        return successfulAuthentication;
    }

    private User buildPrincipal(String name, Collection<? extends GrantedAuthority> authorities) {
        return new User(name, "", authorities);
    }

    private Collection<? extends GrantedAuthority> buildAuthorities(String token) {
        JWTClaimsSet claims = verifyToken(token);
        LOG.trace("Parameters: claims={}", claims);
        List<String> roles = getRolesFromJWT(claims);
        List<? extends GrantedAuthority> authorities = roles.stream().map(r -> new SimpleGrantedAuthority(r))
                .collect(Collectors.toList());
        LOG.trace("Returning: {}", authorities);

        return authorities;
    }

    private List<String> getRolesFromJWT(JWTClaimsSet claims) {
        LOG.trace("Parameters: claims={}", claims);
        List<String> roles = Collections.emptyList();
        try {
            List<String> rolesClaim = claims.getStringListClaim(ROLES_CLAIM);
            if (rolesClaim == null) {
                LOG.warn("token had no '{}' claim.  Principal will have no roles. Claims were: {}", ROLES_CLAIM, claims);
            } else {
                roles = rolesClaim;
            }
        } catch (ParseException e) {
            LOG.warn("token had '{}' claim but was of wrong type.  Principal will have no roles. Claims were: {}", ROLES_CLAIM, claims);
        }

        LOG.trace("Returning: {}", roles);

        return roles;
    }

    private String getSubject(String token) {
        String subject = null;
        try {
            LOG.trace("Parameters: token={}", token);
            JWT jwt = JWTParser.parse(token);
            JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
            subject = claimsSet.getSubject();
        } catch (ParseException e) {
            LOG.debug("Could not determine principal from token as token malformed: {}", token);
            LOG.debug("Malformed token", e);
        }
        LOG.trace("Returning: subject", subject);

        return subject;
    }

    private JWTClaimsSet verifyToken(String token) throws BadCredentialsException {
        LOG.trace("Parameters: token={}", token);
        JWTClaimsSet claims = null;
        try {
            claims = processor.process(token, null);

            LOG.trace("Returning: {}", claims);

            return claims;
        } catch (ParseException | BadJOSEException e) {
            LOG.debug("JWT failed verification: ", e);
            throw new BadCredentialsException("JWT failed verification", e);
        } catch (JOSEException e) {
            throw new Error(e);
        }
    }
}
