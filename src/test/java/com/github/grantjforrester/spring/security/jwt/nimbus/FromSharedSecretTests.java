package com.github.grantjforrester.spring.security.jwt.nimbus;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.Key;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

public class FromSharedSecretTests {

    private FromSharedSecret testee;

    @BeforeEach
    public void setup() throws Exception {
        testee = testee = new FromSharedSecret("aSecret");
    }

    @Test
    public void shouldReturnOneKeyBasedOnSecret() throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).build();
        List<? extends Key> keys = testee.selectJWSKeys(header, null);

        assertThat(keys, hasSize(1));
    }
}
