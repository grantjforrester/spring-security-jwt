# spring-security-jwt 
![Travis (.org)](https://img.shields.io/travis/grantjforrester/spring-security-jwt)
![Codecov](https://img.shields.io/codecov/c/github/grantjforrester/spring-security-jwt)

A lightweight module for Spring Security that provides HTTP request authentication by JSON Web Token (JWT).

When configured all incoming requests to the Spring application are intercepted and must have a valid JWT to be 
authenticated, otherwise a response with status code 401 is returned.

A JWT is valid if:

- it is well-formed
- any "nbf" claim has elapsed
- any "exp" claim has not elapsed
- has the correct signature based on a provided key.

## The Spring Security Context

On successful authentication the `JWTAuthenticationManager` builds a 
[`PreAuthenticatedAuthenticationToken`](https://docs.spring.io/spring-security/site/docs/4.2.12.RELEASE/apidocs/org/springframework/security/web/authentication/preauth/PreAuthenticatedAuthenticationToken.html)
which is set in the current Spring SecurityContext.

The token is populated from the JWT as follows:

- claim `sub` is set as the `principal`
- claim `roles` (an array of strings) is set as the collection of `authorities`
- the JWT itself is set as the `credentials`

> If you want to use Spring's [method security](https://docs.spring.io/spring-security/site/docs/5.1.5.RELEASE/reference/htmlsingle/#ns-method-security)
> then I recommend each string in your `roles` claim has the prefix `ROLE_`.
>
> Example
> ```
> {
>    ...,
>    "roles" : ["ROLE_AddUser", "ROLE_DeleteUser"],
>    ...
> }
> ```

## JWT Signature Checking

To verify a JWT signature a key must be provided.  Two methods of providing a key are supported:

### From Shared Secret

The key is built from a shared secret usually passed in as a configuration value. See class `FromSharedSecret`.

### From KeySet By Kid Claim

Each JWT must specify a "kid" claim in the header.  This value is used to locate a key in the configured
JWKS key set.  See class `FromKeySetByKidClaim`.

## Usage

In your Spring application configure Spring Security as follows:

```java
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${keystore.filename}")
    private Resource keystore;

    @Autowired
    private ApplicationContext context;

    /*
     * Create an authentication filter that looks for a JWT in an "Authorization" header with 
     * the authentication scheme "Bearer".  Use the given JWTAuthenticationManager to 
     * authenticate the JWT.
     */
    @Bean
    Filter authenticationFilter(JWTAuthenticationManager jwtAuthenticationManager) {
        JWTAuthenticationFilter filter = new JWTAuthenticationFilter();
        filter.setTokenProvider(new HeaderJWTProvider("Authorization", "Bearer"));
        filter.setAuthenticationManager(authenticationManager);
        filter.setAuthenticationDetailsSource(new WebAuthenticationDetailsSource());
        return filter;
    }

    /*
     * Create a JWTAuthenticationManager bean responsible for verifying the JWT and setting
     * up the SecurityContext.
     */
    @Bean
    JWTAuthenticationManager jwtAuthenticationManager() {
        FromKeySetByKidClaim keySelector = new FromKeySetByKidClaim(JWKSet.load(keystore.getInputStream()));
        return new NimbusJWTAuthenticationManager(keySelector);
    }

    /*
     * Intercept incoming requests with the JWTAuthenticationFilter. If authentication fails
     * return response with status code 401.
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        Filter authenticationFilter = (Filter) context.getBean("authenticationFilter");
        http.addFilterBefore(authenticationFilter, BasicAuthenticationFilter.class)
            .authorizeRequests().anyRequest().authenticated()
            .and().sessionManagement().sessionCreationPolicy(STATELESS)
            .and().exceptionHandling().authenticationEntryPoint(
                new StatusCode401AuthenticationEntrypoint()
            );
    }
}
```
