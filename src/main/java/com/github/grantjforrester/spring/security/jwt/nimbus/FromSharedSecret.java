package com.github.grantjforrester.spring.security.jwt.nimbus;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.ArrayList;
import java.util.List;

/**
 * Returns a key from a shared secret usually from configuration.
 */
public class FromSharedSecret implements JWSKeySelector<SecurityContext> {

    private static final Logger LOG = LoggerFactory.getLogger(FromSharedSecret.class);

    private final List<SecretKey> keyList = new ArrayList<>();

    /**
     * Creates a new key selector from a shared secret.
     * @param secret the secret
     * @throws NullPointerException if no secret given.
     */
    public FromSharedSecret(String secret) {
        LOG.trace("Parameters: {}", secret);
        if (secret == null) {
            throw new NullPointerException("secret cannot be null");
        }
        SecretKey key = new ImmutableSecret(secret.getBytes()).getSecretKey();
        keyList.add(key);
        LOG.trace("Returning: none");
    }

    /**
     * {@inheritDoc}
     *
     * Returns a list containing one key from the given secret.
     */
    @Override
    public List<? extends Key> selectJWSKeys(JWSHeader jwsHeader, SecurityContext securityContext) {
        LOG.trace("Parameters: {}, {}", jwsHeader, securityContext);
        LOG.trace("Returning: {}}", keyList);
        return keyList;
    }
}
