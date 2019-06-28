# spring-security-jwt
A lightweight module for Spring Security for request authentication by JSON Web Token (JWT).

When configured all incoming requests to the Spring application are intercepted and must have a valid JWT to be 
authenticated, otherwise a response with status code 401 is returned.

A JWT is valid if:

- it is a well-formed
- any "nbf" claim has elapsed
- any "exp" claim has not elapsed
- has a "kid" claim in its header
- the key with the "kid" is present in the application's keyset
- has the correct signature

**Kids and Signature Checking**

Each JWT must specify a "kid" claim in the header.  This value is used to locate a key in the configured
JWKS key set.  The JWT's signature is then verified with the key.  

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
        JWKSetManager keyManager = new JWKSetManager(JWKSet.load(keystore.getInputStream()));
        return new NimbusJWTAuthenticationManager(keyManager);
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
            .and().exceptionHandling().authenticationEntryPoint(new StatusCode401AuthenticationEntrypoint());
    }
}
```
