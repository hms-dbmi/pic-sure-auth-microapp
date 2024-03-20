package edu.harvard.hms.dbmi.avillach.auth.filter;

import edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration;
import edu.harvard.hms.dbmi.avillach.auth.entity.Application;
import edu.harvard.hms.dbmi.avillach.auth.entity.Role;
import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.exceptions.NotAuthorizedException;
import edu.harvard.hms.dbmi.avillach.auth.repository.ApplicationRepository;
import edu.harvard.hms.dbmi.avillach.auth.repository.UserRepository;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.TOSService;
import edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;
import java.util.UUID;

import static edu.harvard.hms.dbmi.avillach.auth.utils.JWTUtil.parseToken;

/**
 * The main gate for PSAMA that filters all incoming requests against PSAMA.
 * <h3>Design Logic</h3>
 * <ul>
 *     <li>All incoming requests pass through this filter.</li>
 *     <li>To pass this filter, the incoming request needs a valid bearer token in its HTTP Authorization Header
 *     to represent a valid identity behind the token. </li>
 *     <li>In some cases, the incoming request doesn't need to hold a token. For example, when the request is to the <code>authentication</code>
 *     endpoint, <code>swagger.json</code>, or <code>swagger.html</code>.</li>
 * </ul>
 */

@Component
public class JWTFilter extends OncePerRequestFilter {

    private final static Logger logger = LoggerFactory.getLogger(JWTFilter.class);

    private final UserRepository userRepo;

    private final ApplicationRepository applicationRepo;

    private final TOSService tosService;

    @Value("${application.user.id.claim}")
    private String USER_CLAIM_ID;

    @Autowired
    public JWTFilter(UserRepository userRepo, ApplicationRepository applicationRepo, TOSService tosService) {
        this.userRepo = userRepo;
        this.applicationRepo = applicationRepo;
        this.tosService = tosService;
    }

    /**
     * Filter implementation that performs authentication and authorization checks based on the provided request headers.
     * The filter checks for the presence of the "Authorization" header and validates the token.
     * It sets the appropriate security context based on the type of token (long term token or PSAMA application token) and
     * performs the necessary checks to ensure that the user or application is authorized to access the requested resource.
     * This filter is called by the configured security filter chain in the SecurityConfig class.
     *
     * @param request     the HttpServletRequest object
     * @param response    the HttpServletResponse object
     * @param filterChain the FilterChain object
     * @throws IOException if an I/O error occurs during the execution of the filter
     */
    @Override
    // Ends that are allowed are handled by the configured security filter chain in the SecurityConfig class
    protected void doFilterInternal(HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws IOException {
        // Get headers from the request
        String authorizationHeader = request.getHeader("Authorization");

        if (!StringUtils.isNotBlank(authorizationHeader)) {
            // If the header is not present, then the request is not authorized
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "No authorization header found.");
        } else {
            // If the header is present, we need to check the token
            String token = authorizationHeader.substring(6).trim();
            logger.debug(" token: {}", token);

            // Parse the token
            Jws<Claims> jws = parseToken(token); // TODO: We shouldn't be implementing a method that should be in the JWTUtils class
            String userId = jws.getBody().get(this.USER_CLAIM_ID, String.class); // TODO: Update when we remove the JAXRSConfiguration class

            if (userId.startsWith(AuthNaming.LONG_TERM_TOKEN_PREFIX)) {
                // For profile information, we do indeed allow long term token
                // to be a valid token.
                if (request.getRequestURI().startsWith("/user/me")) {
                    // Get the subject claim, remove the LONG_TERM_TOKEN_PREFIX, and use that String value to
                    // look up the existing user.
                    String realClaimsSubject = jws.getBody().getSubject().substring(AuthNaming.LONG_TERM_TOKEN_PREFIX.length() + 1);

                    setSecurityContextForUser(request, response, realClaimsSubject);
                } else {
                    logger.error("the long term token with subject, {}, cannot access to PSAMA.", userId);
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Long term tokens cannot be used to access to PSAMA.");
                }

            }

            if (authorizationHeader.startsWith(AuthNaming.PSAMA_APPLICATION_TOKEN_PREFIX)) {
                logger.info("User Authentication Starts with {}", AuthNaming.PSAMA_APPLICATION_TOKEN_PREFIX);

                // Check if user is attempting to access the correct introspect endpoint. If not reject the request
                // log an error indicating the user's token may be being used by a malicious actor.
                if (!request.getRequestURI().endsWith("token/inspect")) {
                    logger.error(userId + " attempted to perform request " + request.getRequestURI() + " token may be compromised.");
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "User is deactivated");
                }

                // Authenticate as Application
                Application authenticatedApplication = applicationRepo.getById(UUID.fromString(userId.split("\\|")[1]));
                if (authenticatedApplication == null) {
                    logger.error("Cannot find an application by userId: " + userId);
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Your token doesn't contain valid identical information, please contact admin.");
                    return;
                }

                if (!authenticatedApplication.getToken().equals(token)) {
                    logger.error("filter() incoming application token - " + token +
                            " - is not the same as record, might because the token has been refreshed. Subject: " + userId);
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Your token has been inactivated, please contact admin to grab you the latest one.");
                }

                // This is the application token that is being used to authenticate the user by other applications
                // Set the security context for the application
                setSecurityContextForApplication(request, authenticatedApplication);
            } else {
                logger.debug("UserID: {} is not a long term token and not a PSAMA application token.", userId);
                // Authenticate as User
                setSecurityContextForUser(request, response, jws.getBody().getSubject());
            }
        }

    }

    private void setSecurityContextForApplication(HttpServletRequest request, Application authenticatedApplication) {
        logger.info("Setting security context for application: {}", authenticatedApplication.getName());
        request.setAttribute("authenticatedApplication", authenticatedApplication);
    }

    // TODO: Implement the ApplicationException thrown in this method

    /**
     * Sets the security context for the given user.
     * This method is responsible for validating the user claims, checking if the user is active,
     * ensuring that the user has accepted the terms of service (if enabled), validating user roles and privileges,
     * and setting the user object as an attribute in the request.
     *
     * @param request           the HttpServletRequest object
     * @param response          the HttpServletResponse object
     * @param realClaimsSubject the subject of the user's claims in the JWT token
     */
    private void setSecurityContextForUser(HttpServletRequest request, HttpServletResponse response, String realClaimsSubject) {
        logger.info("Setting security context for user: {}", realClaimsSubject);

        User authenticatedUser = userRepo.findBySubject(realClaimsSubject);

        if (authenticatedUser == null) {
            logger.error("Cannot validate user claims, based on information stored in the JWT token.");
            throw new IllegalArgumentException("Cannot validate user claims, based on information stored in the JWT token.");
        }

        if (!authenticatedUser.isActive()) {
            logger.warn("User with ID: " + authenticatedUser.getUuid() + " is deactivated.");
            throw new NotAuthorizedException("User is deactivated");
        }

        if (JAXRSConfiguration.tosEnabled.startsWith("true") && tosService.getLatest() != null && !tosService.hasUserAcceptedLatest(authenticatedUser.getSubject())) {
            //If user has not accepted terms of service and is attempted to get information other than the terms of service, don't authenticate
            try {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "User must accept terms of service");
            } catch (IOException e) {
                logger.error("Failed to send response.", e);
            }
        }

        // Get the user's roles
        Set<Role> userRoles = authenticatedUser.getRoles();

        // Check if the user has any roles and privileges associated with them
        if (userRoles == null || userRoles.isEmpty() || userRoles.stream().noneMatch(role -> role.getPrivileges() != null && !role.getPrivileges().isEmpty())) {
            logger.error("User doesn't have any roles or privileges.");
            try {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "User doesn't have any roles or privileges.");
            } catch (IOException e) {
                logger.error("Failed to send response.", e);
            }
        }

        // TODO: Spring is generally expecting ROLE_ prefix for roles. We may need to add this prefix to all the user roles.
        // We don't want to add this to the database, because it may break backward compatibility for the UI.
        request.setAttribute("authenticatedUser", authenticatedUser);
    }

}