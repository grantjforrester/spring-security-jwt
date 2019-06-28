package com.github.grantjforrester.springsecurityjwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.net.URL;
import java.security.Key;
import java.util.List;

import static com.nimbusds.jose.jwk.JWKSet.load;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

public class JWKSetManagerTests {

    private JWKSetManager testee;

    @BeforeEach
    public void setup() throws Exception {
        URL url = this.getClass().getResource("/testkeyset.jwks");
        File keySetFile = new File(url.toURI());
        testee = new JWKSetManager(load(keySetFile));
    }

    @Test
    public void shouldReturnNullWhenKeyNotFoundById() throws Exception {
        JWK key = testee.getJWKByKid("missing");

        assertThat(key, is(nullValue()));
    }

    @Test
    public void shouldReturnKeyWhenSharedSecretKeyFoundById() throws Exception {
        JWK key = testee.getJWKByKid("dev-hmac");

        assertThat(key, is(notNullValue()));
        assertThat(key, is(instanceOf(OctetSequenceKey.class)));
    }

    @Test
    public void shouldReturnKeyWhenRSAKeyFoundById() throws Exception {
        JWK key = testee.getJWKByKid("dev-rsa");

        assertThat(key, is(notNullValue()));
        assertThat(key, is(instanceOf(RSAKey.class)));
    }

    @Test
    public void shouldReturnKeyWhenECKeyFoundById() throws Exception {
        JWK key = testee.getJWKByKid("dev-ec");

        assertThat(key, is(notNullValue()));
        assertThat(key, is(instanceOf(ECKey.class)));
    }


    @Test
    public void shouldReturnEmptyListWhenKeyNotFoundFromHeader() throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("missing").build();
        List<? extends Key> keys = testee.selectJWSKeys(header, null);

        assertThat(keys, is(empty()));
    }

    @Test
    public void shouldReturnKeysInListWhenSharedSecretKeyFoundFromHeader() throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("dev-hmac").build();
        List<? extends Key> keys = testee.selectJWSKeys(header, null);

        assertThat(keys, hasSize(1));
    }

    @Test
    public void shouldReturnKeysInListWhenRSAKeyFoundFromHeader() throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("dev-rsa").build();
        List<? extends Key> keys = testee.selectJWSKeys(header, null);

        assertThat(keys, hasSize(1 /*public*/ + 1 /*private*/));
    }

    @Test
    public void shouldReturnKeysInListWhenECKeyFoundFromHeader() throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("dev-ec").build();
        List<? extends Key> keys = testee.selectJWSKeys(header, null);

        assertThat(keys, hasSize(1 /*public*/ + 1 /*private*/));
    }
}
