package com.github.grantjforrester.spring.security.jwt.nimbus;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyConverter;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Key;
import java.util.Collections;
import java.util.List;

/**
 * Returns a key from a JWKS keyset identified by the 'kid' claim in the JTW header.
 *
 * See <a href="https://tools.ietf.org/html/rfc7517">RFC 7517: JSON Web Key (JWK)</a>
 */
public class FromKeySetByKidClaim implements JWSKeySelector<SecurityContext> {

    private static final Logger LOG = LoggerFactory.getLogger(FromKeySetByKidClaim.class);

    private final JWKSet keyset;

    /**
     * Creates a new key selector with an JWK set.
     * @param keyset the JWK set.
     * @throws NullPointerException if no JWK set given.
     */
    public FromKeySetByKidClaim(JWKSet keyset) {
        LOG.trace("Parameters: {}", keyset);
        if (keyset == null) {
            throw new NullPointerException("keyset cannot be null");
        }
        this.keyset = keyset;
        LOG.trace("Returning: none");
    }

    /**
     * {@inheritDoc}
     *
     * Attempts to return a key for the JWK set specified by the <code>kid</code> claim in the JWS header.
     * If the <code>kid</code> is not present in the header, or no JWK was found then an empty list is returned.
     */
    @Override
    public List<? extends Key> selectJWSKeys(JWSHeader jwsHeader, SecurityContext securityContext) {
        LOG.trace("Parameters: {}, {}", jwsHeader, securityContext);
        List<? extends Key> keys = Collections.emptyList();
        String keyId = jwsHeader.getKeyID();
        JWK key = getJWKByKid(keyId);
        if (key != null) {
            keys = KeyConverter.toJavaKeys(Collections.singletonList(key));
        }
        LOG.trace("Returning: {}", keys);

        return keys;
    }

    JWK getJWKByKid(String kid) {
        LOG.trace("Parameters: {}", kid);
        JWK jwk = keyset.getKeyByKeyId(kid);
        LOG.trace("Returning: {}", jwk);

        return jwk;
    }
}
