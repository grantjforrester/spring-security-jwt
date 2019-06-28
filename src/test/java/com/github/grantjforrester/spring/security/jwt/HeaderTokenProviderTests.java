package com.github.grantjforrester.spring.security.jwt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Optional;

import static com.github.npathai.hamcrestopt.OptionalMatchers.isEmpty;
import static com.github.npathai.hamcrestopt.OptionalMatchers.isPresentAndIs;
import static org.hamcrest.MatcherAssert.assertThat;

public class HeaderTokenProviderTests {

    private HeaderJWTProvider testee;
    private MockHttpServletRequest request;

    @BeforeEach
    public void setup() throws Exception {
        testee = new HeaderJWTProvider();
    }

    @BeforeEach
    public void setupMocks() throws Exception {
        request = new MockHttpServletRequest();
    }

    @Test
    public void shouldReturnEmptyWhenNoHeader() throws Exception {

        // When
        Optional<String> actualToken = testee.getJWTFromRequest(request);

        // Then
        assertThat(actualToken, isEmpty());
    }

    @Test
    public void shouldReturnEmptyWhenHeaderHasWrongAuthScheme() throws Exception {
        // Then
        request.addHeader("Authorization", "Basic ehf9ded8ebwqiudiwiuu");
        // When
        Optional<String> actualToken = testee.getJWTFromRequest(request);

        // Then
        assertThat(actualToken, isEmpty());
    }

    @Test
    public void shouldReturnEmptyWhenHeaderMissingToken() throws Exception {
        // Then
        request.addHeader("Authorization", "Bearer");
        // When
        Optional<String> actualToken = testee.getJWTFromRequest(request);

        // Then
        assertThat(actualToken, isEmpty());
    }

    @Test
    public void shouldReturnTokenWhenHeaderContainsToken() throws Exception {
        // Then
        String token = "someToken";
        request.addHeader("Authorization", "Bearer " + token);

        // When
        Optional<String> actualToken = testee.getJWTFromRequest(request);

        // Then
        assertThat(actualToken, isPresentAndIs(token));
    }
}
