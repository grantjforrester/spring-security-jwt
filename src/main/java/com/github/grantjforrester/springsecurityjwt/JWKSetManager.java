package com.github.grantjforrester.springsecurityjwt;

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
 * Manages a collection of JWKs and provides methods for returning JWKs and Keys by the JWK keyId.
 *
 * See <a href="https://tools.ietf.org/html/rfc7517">RFC 7517: JSON Web Key (JWK)</a>
 */
public class JWKSetManager implements JWSKeySelector<SecurityContext> {

    private static final Logger LOG = LoggerFactory.getLogger(JWKSetManager.class);
    private final JWKSet keyset;

    /**
     * Creates a new manager with an existing JWK set.
     * @param keyset the JWK set.
     * @throws NullPointerException if no JWK set given.
     */
    public JWKSetManager(JWKSet keyset) {
        LOG.trace("Parameters: keyset={}", keyset);
        if (keyset == null) {
            throw new NullPointerException("keyset cannot be null");
        }
        this.keyset = keyset;
        LOG.trace("Returning: none");
    }

    /**
     * Attempts to return all defined keys for the JWK in the set specified by the <code>kid</code> claim in the JWS header.
     * If the <code>kid</code> is not present in the header, or no JWK was found then an empty list is returned.
     */
    @Override
    public List<? extends Key> selectJWSKeys(JWSHeader jwsHeader, SecurityContext securityContext) {
        List<? extends Key> keys = Collections.emptyList();
        String keyId = jwsHeader.getKeyID();
        JWK key = getJWKByKid(keyId);
        if (key != null) {
            keys = KeyConverter.toJavaKeys(Collections.singletonList(key));
        }
        LOG.trace("Returning: {}", keys);

        return keys;
    }

    /**
     * Returns a JWK from the JWK set with the given <code>kid</code>.
     * @param kid the unique id of the key
     * @return the JWK or null is no JWK found.
     */
    public JWK getJWKByKid(String kid) {
        LOG.trace("Parameters: kid={}", kid);
        JWK jwk = keyset.getKeyByKeyId(kid);
        LOG.trace("Returning: {}", jwk);

        return jwk;
    }
}
