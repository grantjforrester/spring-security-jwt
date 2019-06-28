package com.github.grantjforrester.springsecurityjwt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.io.File;
import java.net.URL;
import java.util.Optional;

import static com.github.grantjforrester.springsecurityjwt.JWTTestUtils.EXPIRED_JWT;
import static com.github.grantjforrester.springsecurityjwt.JWTTestUtils.JWT_WITH_EC_SIG;
import static com.github.grantjforrester.springsecurityjwt.JWTTestUtils.JWT_WITH_HMAC_SIG;
import static com.github.grantjforrester.springsecurityjwt.JWTTestUtils.JWT_WITH_INVALID_SIG;
import static com.github.grantjforrester.springsecurityjwt.JWTTestUtils.JWT_WITH_NO_KID;
import static com.github.grantjforrester.springsecurityjwt.JWTTestUtils.JWT_WITH_RSA_SIG;
import static com.github.grantjforrester.springsecurityjwt.JWTTestUtils.JWT_WITH_UNKNOWN_KID;
import static com.github.grantjforrester.springsecurityjwt.JWTTestUtils.MALFORMED_JWT;
import static com.github.npathai.hamcrestopt.OptionalMatchers.isEmpty;
import static com.github.npathai.hamcrestopt.OptionalMatchers.isPresent;
import static com.googlecode.catchexception.CatchException.catchException;
import static com.googlecode.catchexception.CatchException.caughtException;
import static com.nimbusds.jose.jwk.JWKSet.load;
import static java.util.Collections.emptySet;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;


public class NimbusJWTAuthenticationManagerTests {

    private NimbusJWTAuthenticationManager testee;

    @BeforeEach
    public void setup() throws Exception {
        URL url = this.getClass().getResource("/testkeyset.jwks");
        File keySetFile = new File(url.toURI());
        JWKSetManager keysetManager = new JWKSetManager(load(keySetFile));
        testee = new NimbusJWTAuthenticationManager(keysetManager);
    }

    @Test
    public void shouldNotReturnPrincipalIfJWTMalformed() throws Exception {
        // Given
        String jwt = MALFORMED_JWT;

        // When
        Optional<Object> actualPrincipal =  testee.getPrincipalFrom(jwt);

        // Then
        assertThat(actualPrincipal, isEmpty());
    }

    @Test
    public void shouldNotReturnPrincipalIfNoSubjectClaim() throws Exception {
        // Given
        String jwt = "token without subject";

        // When
        Optional<Object> actualResult =  testee.getPrincipalFrom(jwt);

        // Then
        assertThat(actualResult, isEmpty());
    }

    @Test
    public void shouldReturnPrincipalIfJWTHasSubjectClaim() throws Exception {
        // Given
        String jwt = JWT_WITH_HMAC_SIG;
        String subject = "John Smith";

        // When
        Optional<Object> actualResult =  testee.getPrincipalFrom(jwt);

        // Then
        assertThat(actualResult, isPresent());
        User actualUser = (User) actualResult.get();
        assertThat(actualUser, is(equalTo(new User(subject, "", emptySet()))));
    }

    @Test
    public void shouldNotAuthenticateIfNoKeyId() throws Exception {
        // Given
        String jwt = JWT_WITH_NO_KID;
        User user = new User("anyName", "anyPassword", emptySet());
        Authentication auth = new TestingAuthenticationToken(user, jwt);

        // When
        catchException(() -> testee.authenticate(auth));

        // Then
        assertThat(caughtException(), is(instanceOf(BadCredentialsException.class)));
    }

    @Test
    public void shouldNotAuthenticateIfUnknownKey() throws Exception {
        // Given
        String jwt = JWT_WITH_UNKNOWN_KID;
        User user = new User("anyName", "anyPassword", emptySet());
        Authentication auth = new TestingAuthenticationToken(user, jwt);

        // When
        catchException(() -> testee.authenticate(auth));

        // Then
        assertThat(caughtException(), is(instanceOf(BadCredentialsException.class)));
    }

    @Test
    public void shouldNotAuthenticateIfJWTInvalidSig() throws Exception {
        // Given
        String jwt = JWT_WITH_INVALID_SIG;
        User user = new User("anyName", "anyPassword", emptySet());
        Authentication auth = new TestingAuthenticationToken(user, jwt);

        // When
        catchException(() -> testee.authenticate(auth));

        // Then
        assertThat(caughtException(), is(instanceOf(BadCredentialsException.class)));
    }

    @Test
    public void shouldNotAuthenticateIfJWTExpired() throws Exception {
        // Given
        String jwt = EXPIRED_JWT;
        User user = new User("anyName", "anyPassword", emptySet());
        Authentication auth = new TestingAuthenticationToken(user, jwt);

        // When
        catchException(() -> testee.authenticate(auth));

        // Then
        assertThat(caughtException(), is(instanceOf(BadCredentialsException.class)));
    }

    @Test
    public void shouldAuthenticateIfJWTWithHmacSigIsValid() throws Exception {
        // Given
        String role = "someRole";
        String token = JWT_WITH_HMAC_SIG;
        User user = new User("anyName", "anyPassword", emptySet());
        Authentication auth = new TestingAuthenticationToken(user, token);

        // When
        Authentication successfulAuth = testee.authenticate(auth);

        // Then
        assertThat(successfulAuth.isAuthenticated(), is(equalTo(true)));
        assertThat(successfulAuth.getAuthorities(), contains(new SimpleGrantedAuthority(role)));
    }

    @Test
    public void shouldAuthenticateIfJWTWithRSASigIsValid() throws Exception {
        // Given
        String role = "someRole";
        String token = JWT_WITH_RSA_SIG;
        User user = new User("anyName", "anyPassword", emptySet());
        Authentication auth = new TestingAuthenticationToken(user, token);

        // When
        Authentication successfulAuth = testee.authenticate(auth);

        // Then
        assertThat(successfulAuth.isAuthenticated(), is(equalTo(true)));
        assertThat(successfulAuth.getAuthorities(), contains(new SimpleGrantedAuthority(role)));
    }

    @Test
    public void shouldAuthenticateIfJWTWithECSigIsValid() throws Exception {
        // Given
        String role = "someRole";
        String token = JWT_WITH_EC_SIG;
        User user = new User("anyName", "anyPassword", emptySet());
        Authentication auth = new TestingAuthenticationToken(user, token);

        // When
        Authentication successfulAuth = testee.authenticate(auth);

        // Then
        assertThat(successfulAuth.isAuthenticated(), is(equalTo(true)));
        assertThat(successfulAuth.getAuthorities(), contains(new SimpleGrantedAuthority(role)));
    }
}
