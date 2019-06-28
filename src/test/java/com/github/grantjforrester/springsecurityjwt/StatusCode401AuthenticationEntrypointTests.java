package com.github.grantjforrester.springsecurityjwt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.InsufficientAuthenticationException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

public class StatusCode401AuthenticationEntrypointTests {

    private StatusCode401AuthenticationEntrypoint testee;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    public void setup() {
        testee = new StatusCode401AuthenticationEntrypoint();
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    public void shouldAlwaysReturn401ErrorWithMessageFromException() throws Exception {
        String errorMessage = "No token";

        testee.commence(request, response, new InsufficientAuthenticationException(errorMessage) );

        assertThat(response.getStatus(), is(equalTo(401)));
        assertThat(response.getErrorMessage(), is(equalTo(errorMessage)));
    }
}
