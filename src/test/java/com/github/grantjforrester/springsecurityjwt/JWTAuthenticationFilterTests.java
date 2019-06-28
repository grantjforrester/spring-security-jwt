package com.github.grantjforrester.springsecurityjwt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class JWTAuthenticationFilterTests {

   private JWTAuthenticationFilter testee;
   private JWTProvider tokenProvider;
   private JWTAuthenticationManager tokenAuthenticationManager;
   private MockHttpServletRequest request;
   private MockHttpServletResponse response;
   private MockFilterChain filterChain;

   @BeforeEach
   public void setup() throws Exception {
       tokenProvider = Mockito.mock(JWTProvider.class);
       tokenAuthenticationManager = Mockito.mock(JWTAuthenticationManager.class);
       request = new MockHttpServletRequest();
       response = new MockHttpServletResponse();
       filterChain = new MockFilterChain();

       testee = new JWTAuthenticationFilter();
       testee.setJwtProvider(tokenProvider);
       testee.setAuthenticationManager(tokenAuthenticationManager);
   }

   @Test
   public void shouldNotBeAuthenticatedIfNoTokenFound() throws Exception {
       // Given
       when(tokenProvider.getJWTFromRequest(any())).thenReturn(Optional.empty());

       // When
       testee.doFilter(request, response, filterChain);
       Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

       // Then
       assertThat(authentication, is(nullValue()));
   }

   @Test
   public void shouldNotBeAuthenticatedIfNoPrincipalInToken() throws Exception {
       // Given
       when(tokenProvider.getJWTFromRequest(any())).thenReturn(Optional.of("someTokenValue"));
       when(tokenAuthenticationManager.getPrincipalFrom(any())).thenReturn(Optional.empty());

       // When
       testee.doFilter(request, response, filterChain);
       Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

       // Then
       assertThat(authentication, is(nullValue()));
   }

   @Test
   public void shouldNotBeAuthenticatedIfAuthenticationFails() throws Exception {
       // Given
       when(tokenProvider.getJWTFromRequest(any())).thenReturn(Optional.of("someTokenValue"));
       when(tokenAuthenticationManager.getPrincipalFrom(any())).thenReturn(Optional.of(mock(User.class)));
       when(tokenAuthenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("bad"));

       // When
       testee.doFilter(request, response, filterChain);
       Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

       // Then
       assertThat(authentication, is(nullValue()));
   }

   @Test
   public void shouldSetSecurityContextIfAuthenticationSuccessful() throws Exception {
       // Given
       Authentication authenticated = Mockito.mock(Authentication.class);
       when(tokenProvider.getJWTFromRequest(any())).thenReturn(Optional.of("someTokenValue"));
       when(tokenAuthenticationManager.getPrincipalFrom(any())).thenReturn(Optional.of(mock(User.class)));
       when(tokenAuthenticationManager.authenticate(any())).thenReturn(authenticated);

       // When
       testee.doFilter(request, response, filterChain);
       Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

       // Then
       assertThat(authentication, is(equalTo(authenticated)));
   }
}
