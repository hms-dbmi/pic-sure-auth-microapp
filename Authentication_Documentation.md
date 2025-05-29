# Authentication System Documentation

## Overview

This document provides comprehensive documentation on the authentication system in the PIC-SURE Auth Microapp. It covers the JWT-based authentication flow, Spring Security configuration, role-based access control, and other important aspects of the authentication process.

## Table of Contents

1. [Authentication Flow](#authentication-flow)
2. [JWT Filter](#jwt-filter)
3. [JWT Token Management](#jwt-token-management)
4. [Spring Security Configuration](#spring-security-configuration)
5. [Role-Based Access Control](#role-based-access-control)
6. [Token Types](#token-types)
7. [Best Practices](#best-practices)

## Authentication Flow

The authentication flow in PIC-SURE Auth Microapp follows these steps:

1. **Client Request**: The client sends a request to the server with an Authorization header containing a JWT token.
2. **JWT Validation**: The JWTFilter intercepts the request and validates the JWT token.
3. **Security Context Setup**: If the token is valid, the filter sets up the security context with the user's details and authorities.
4. **Authorization Check**: The system checks if the authenticated user has the required roles to access the requested resource.
5. **Response**: If all checks pass, the request is processed; otherwise, an appropriate error response is returned.

## JWT Filter

The JWTFilter is the main entry point for authentication in the PIC-SURE Auth Microapp. It extends Spring's OncePerRequestFilter and processes all incoming requests.

### Filter Responsibilities

- Intercepts all incoming HTTP requests
- Extracts and validates JWT tokens from the Authorization header
- Sets up the security context based on the token's claims
- Handles different types of tokens (user tokens, long-term tokens, application tokens)
- Performs additional checks like Terms of Service acceptance

### Filter Flow

1. **Token Extraction**: The filter extracts the JWT token from the Authorization header.
2. **Token Validation**: The token is validated using the JWTUtil service.
3. **User Identification**: The filter identifies the user or application based on the token's claims.
4. **Token Type Handling**:
   - For long-term tokens: Limited access is granted (only to specific endpoints)
   - For application tokens: Application-specific security context is set up
   - For regular user tokens: User-specific security context is set up
5. **Additional Checks**:
   - For user tokens: The filter checks if the user is active and has accepted the latest Terms of Service
   - For all tokens: The filter verifies that the user or application has appropriate roles and privileges

### Code Example

```java
@Override
protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
    // Get headers from the request
    String authorizationHeader = request.getHeader("Authorization");

    if (!StringUtils.isNotBlank(authorizationHeader)) {
        // If the header is not present, we allow the request to pass through
        // without any authentication or authorization checks
        filterChain.doFilter(request, response);
    } else {
        String token = authorizationHeader.substring(6).trim();
        Jws<Claims> jws = this.jwtUtil.parseToken(token);
        String userId = jws.getPayload().get(this.userClaimId, String.class);

        // Handle different token types
        if (userId.startsWith(AuthNaming.LONG_TERM_TOKEN_PREFIX)) {
            // Handle long-term token
            // ...
        } else if (userId.startsWith(AuthNaming.PSAMA_APPLICATION_TOKEN_PREFIX)) {
            // Handle application token
            // ...
        } else {
            // Handle regular user token
            // ...
        }

        filterChain.doFilter(request, response);
    }
}
```

## JWT Token Management

JWT tokens are managed by the JWTUtil class, which provides methods for creating, validating, and parsing tokens.

### Token Creation

Tokens are created with the following components:
- **ID**: A unique identifier for the token
- **Issuer**: The entity that issued the token
- **Subject**: The subject of the token (typically the user ID)
- **Claims**: Additional data stored in the token
- **Expiration**: When the token expires
- **Signature**: A cryptographic signature to verify the token's authenticity

### Token Validation

When validating a token, the system:
1. Verifies the token's signature using the application's client secret
2. Checks if the token has expired
3. Extracts the claims from the token for further processing

### Token Refresh

The system supports token refreshing based on the token's expiration time:
- If a token is approaching its expiration time (halfway through its lifetime), it can be refreshed
- The refresh process creates a new token with the same claims but a new expiration time

### Code Example

```java
public String createJwtToken(String id, String issuer, Map<String, Object> claims, String subject, long ttlMillis) {
    // Set default TTL if not specified
    if (ttlMillis < 0) {
        ttlMillis = defaultTTLMillis;
    }

    // Create token with specified parameters
    long nowMillis = System.currentTimeMillis();
    Date now = new Date(nowMillis);

    String clientSecret = getDecodedClientSecret();
    SecretKey signingKey = Keys.hmacShaKeyFor(clientSecret.getBytes(StandardCharsets.UTF_8));

    JwtBuilder builder = Jwts.builder()
            .claims(claims)
            .id(id)
            .issuedAt(now)
            .subject(subject)
            .issuer(issuer)
            .signWith(signingKey);

    // Add expiration
    long expMillis = nowMillis + ttlMillis;
    Date exp = new Date(expMillis);
    builder.expiration(exp);

    return builder.compact();
}
```

## Spring Security Configuration

The Spring Security configuration defines the security filter chain and authentication providers for the application.

### Security Filter Chain

The security filter chain is configured to:
- Disable CSRF protection (as JWT tokens provide protection against CSRF attacks)
- Use stateless session management (typical for JWT-based authentication)
- Permit access to specific endpoints without authentication (like /authentication, /swagger.json)
- Require authentication for all other requests
- Add the JWTFilter before the UsernamePasswordAuthenticationFilter
- Configure a custom logout handler

### Method Security

Method-level security is enabled using JSR-250 annotations:
- `@EnableMethodSecurity(jsr250Enabled = true)` enables the use of `@RolesAllowed` annotations
- The default "ROLE_" prefix is removed to simplify role names

### Code Example

```java
@Configuration
@EnableMethodSecurity(prePostEnabled = false, jsr250Enabled = true)
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .sessionManagement((session) -> session.sessionCreationPolicy(STATELESS))
                .authenticationProvider(authenticationProvider)
                .authorizeHttpRequests((authorizeRequests) ->
                    authorizeRequests.requestMatchers(
                                "/authentication",
                                "/swagger.yaml",
                                "/actuator/health"
                            ).permitAll()
                            .anyRequest().authenticated()
                )
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                ;

        return http.build();
    }

    @Bean
    public GrantedAuthorityDefaults grantedAuthorityDefaults() {
        return new GrantedAuthorityDefaults(""); // Remove the default "ROLE_" prefix
    }
}
```

## Role-Based Access Control

Role-based access control is implemented using the `@RolesAllowed` annotation, which restricts access to methods based on the user's roles.

### Role Hierarchy

The system defines two main roles:
- **ADMIN**: Standard administrator role with access to most administrative functions
- **SUPER_ADMIN**: Higher-level administrator role with access to all functions, including sensitive operations

### Method-Level Security

The `@RolesAllowed` annotation is used on controller methods to restrict access:
- `@RolesAllowed(SUPER_ADMIN)`: Only users with the SUPER_ADMIN role can access
- `@RolesAllowed({ADMIN, SUPER_ADMIN})`: Users with either ADMIN or SUPER_ADMIN roles can access

### Code Example

```java
@RestController
@RequestMapping("/user")
public class UserController {

    @GetMapping("/")
    @RolesAllowed({ADMIN, SUPER_ADMIN})
    public List<User> getAllUsers() {
        // Method accessible to both ADMIN and SUPER_ADMIN
        // ...
    }

    @DeleteMapping("/{id}")
    @RolesAllowed(SUPER_ADMIN)
    public void deleteUser(@PathVariable String id) {
        // Method accessible only to SUPER_ADMIN
        // ...
    }
}
```

## Token Types

The system supports different types of tokens for various authentication scenarios.

### User Tokens

- **Purpose**: Regular authentication for users
- **Prefix**: None (standard JWT token)
- **Usage**: Used for most API requests
- **Validation**: Checks user status, Terms of Service acceptance, roles, and privileges

### Long-Term Tokens

- **Purpose**: Extended authentication for specific use cases
- **Prefix**: LONG_TERM_TOKEN
- **Usage**: Limited to specific endpoints (e.g., /auth/user/me)
- **Validation**: Similar to user tokens but with restrictions on accessible endpoints

### Application Tokens

- **Purpose**: Authentication for application-to-application communication
- **Prefix**: PSAMA_APPLICATION
- **Usage**: Used for token inspection and validation endpoints
- **Validation**: Checks application status and token validity

## Best Practices

1. **Token Security**:
   - Store tokens securely on the client side
   - Use HTTPS for all API requests
   - Set appropriate token expiration times

2. **Role Assignment**:
   - Follow the principle of least privilege
   - Assign the minimum necessary roles to users
   - Regularly review and audit role assignments

3. **Token Management**:
   - Implement token refresh mechanisms for long-lived sessions
   - Invalidate tokens when users log out or change passwords
   - Consider using token blacklisting for sensitive applications

4. **Error Handling**:
   - Return appropriate HTTP status codes for authentication failures
   - Avoid exposing sensitive information in error messages
   - Log authentication failures for security monitoring
