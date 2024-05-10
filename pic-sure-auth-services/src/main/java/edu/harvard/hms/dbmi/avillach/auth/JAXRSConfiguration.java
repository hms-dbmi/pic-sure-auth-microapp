package edu.harvard.hms.dbmi.avillach.auth;


import com.fasterxml.jackson.databind.ObjectMapper;
import edu.harvard.hms.dbmi.avillach.auth.data.entity.Connection;
import edu.harvard.hms.dbmi.avillach.auth.data.entity.Privilege;
import edu.harvard.hms.dbmi.avillach.auth.data.entity.Role;
import edu.harvard.hms.dbmi.avillach.auth.data.repository.ConnectionRepository;
import edu.harvard.hms.dbmi.avillach.auth.data.repository.PrivilegeRepository;
import edu.harvard.hms.dbmi.avillach.auth.data.repository.RoleRepository;
import edu.harvard.hms.dbmi.avillach.auth.rest.TokenService;
import io.swagger.jaxrs.config.BeanConfig;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.inject.Inject;
import javax.mail.Session;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.SecurityContext;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming.AuthRoleNaming.ADMIN;
import static edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming.AuthRoleNaming.SUPER_ADMIN;

/**
 * <p>When you deploy the PSAMA application WAR file to a new server, this class is called to supply basic configuration information.</p>
 */
@Startup
@Singleton(name = "JAXRSConfiguration")
@ApplicationPath("auth")
public class JAXRSConfiguration extends Application {

    private Logger logger = LoggerFactory.getLogger(JAXRSConfiguration.class);

    @Resource(mappedName = "java:global/client_secret")
    public static String clientSecret; // actually picsure_client_secret in standalone.xml
    @Resource(mappedName = "java:global/clientSecretIsBase64")
    public static String clientSecretIsBase64;

    @Resource(mappedName = "java:global/user_id_claim")
    public static String userIdClaim;

    @Resource(mappedName = "java:global/auth0host")
    public static String auth0host;

    @Resource(mappedName = "java:global/tosEnabled")
    public static String tosEnabled;

    /**
     * The default application UUID assumed for all operational contexts where
     * one is not supplied.
     */
    @Resource(mappedName = "java:global/defaultApplicationUUID")
    public static String defaultApplicationUUID;

    @Resource(mappedName = "java:global/systemName")
    public static String systemName;

    @Resource(mappedName = "java:global/templatePath")
    public static String templatePath;

    @Resource(mappedName = "java:global/accessGrantEmailSubject")
    public static String accessGrantEmailSubject;

    @Resource(mappedName = "java:global/userActivationReplyTo")
    public static String userActivationReplyTo;

    @Resource(lookup = "java:jboss/mail/gmail")
    public static Session mailSession;

    @Resource(lookup = "java:global/adminUsers")
    public static String adminUsers;

    @Resource(lookup = "java:global/deniedEmailEnabled")
    public static String deniedEmailEnabled;

    @Resource(lookup = "java:global/variantAnnotationColumns")
    public static String variantAnnotationColumns;

    // See checkIDPProvider method for setting these variables
    public static String idp_provider;
    public static String idp_provider_uri;
    public static String fence_client_id;
    public static String fence_client_secret;
    public static String fence_redirect_url;
    public static String fence_parent_consent_group_concept_path;
    public static String fence_standard_access_rules;
    public static String fence_harmonized_concept_path;
    public static String fence_harmonized_consent_group_concept_path;
    public static String fence_topmed_consent_group_concept_path;
    public static String fence_allowed_query_types;
    public static String defaultAdminRoleName = "PIC-SURE Top Admin";
    public static String spClientSecret;
    public static String connectionId;
    public static String clientId;
    public static long tokenExpirationTime;
    // default expiration time is 1 hr
    private static long defaultTokenExpirationTime = 1000L * 60 * 60;
    public static long longTermTokenExpirationTime;
    // default long term token expiration time is 30 days
    private static long defaultLongTermTokenExpirationTime = 1000L * 60 * 60 * 24 * 30;

    @Inject
    RoleRepository roleRepo;

    @Inject
    PrivilegeRepository privilegeRepo;

    @Inject
    ConnectionRepository connectionRepo;

    public final static ObjectMapper objectMapper = new ObjectMapper();

    public static final HttpClient client = HttpClientBuilder.create().build();


    @PostConstruct
    public void init() {
        logger.info("Starting auth micro app");

        logger.info("Start initializing JNDI context");
        Context ctx;
        try {
            ctx = new InitialContext();
        } catch (NamingException e) {
            // If we can't get the context, we can't do anything
            throw new RuntimeException("Failed to initialize JNDI context", e);
        }

        /*
            create an admin role if there isn't one
         */
        logger.info("Start initializing admin role in database");
        initializeDefaultAdminRole();
        logger.info("Finished initializing admin role.");

        logger.info("Start initializing tokens expiration time.");
        initializeTokenExpirationTime(ctx);
        initializeLongTermTokenExpirationTime(ctx);
        logger.info("Finished initializing token expiration time.");

        checkIDPProvider(ctx);

        if (mailSession != null) {
            mailSession.getProperties().put("mail.smtp.ssl.trust", "smtp.gmail.com");
        }

        //Set info for the swagger.json
        BeanConfig beanConfig = new BeanConfig();
        beanConfig.setVersion("1.0.1");
        beanConfig.setSchemes(new String[]{"https"});
        beanConfig.setDescription("APIs for accessing PIC-SURE-AUTH-MICROAPP - a centralized authentication/authorization micro services");
        beanConfig.setTitle("PIC-SURE-AUTH-MICROAPP");
        beanConfig.setBasePath("/psama");
        beanConfig.setResourcePackage(TokenService.class.getPackage().getName());
        beanConfig.setScan(true);
        logger.info("Auth micro app has been successfully started");
    }

    /*
     * Check if the IDP provider is set, and if it is, then determine additional
     * settings.
     *
     * If flag is missing, or empty, the default is Auth0 configuration.
     *
     * This is currently only works for FENCE integration.
     *
     */
    public void checkIDPProvider(Context ctx) {
        logger.debug("checkIDPProvider() starting....");

        try {
            idp_provider = (String) ctx.lookup("java:global/idp_provider");
        } catch (NamingException | ClassCastException | NumberFormatException ex) {
            idp_provider = "default";
        }
        logger.info("checkIDPProvider() idp provider is now :{}", idp_provider);

        if (idp_provider.equalsIgnoreCase("fence")) {
            try {
                idp_provider_uri = (String) ctx.lookup("java:global/idp_provider_uri");
                fence_client_id = (String) ctx.lookup("java:global/fence_client_id");
                fence_client_secret = (String) ctx.lookup("java:global/fence_client_secret");
                fence_redirect_url = (String) ctx.lookup("java:global/fence_redirect_url");

                getFenceParentConsentGroupConceptPath(ctx);
                getFenceHarmonizaedGroupConsentPath(ctx);
                getFenceTopmedConsentGroupPath(ctx);
                getFenceStandardAccessRules(ctx);
                getFenceAllowedQueryTypes(ctx);
                getFenceHarmonizedConceptPath(ctx);

                logger.debug("checkIDPProvider() idp provider FENCE is configured");

                // Upsert FENCE connection
                Connection c = connectionRepo.getUniqueResultByColumn("label", "FENCE");
                if (c != null) {
                    logger.debug("checkIDPProvider() FENCE connection already exists.");
                } else {
                    logger.debug("checkIDPProvider() Create new FENCE connection");
                    c = new Connection();
                    c.setLabel("FENCE");
                    c.setId("fence");
                    c.setSubPrefix("fence|");
                    c.setRequiredFields("[{\"label\":\"email\",\"id\":\"email\"}]");
                    connectionRepo.persist(c);
                    logger.debug("checkIDPProvider() New FENCE connetion has been created");
                }

                // For debugging purposes, here is a dump of most of the FENCE variables
                logger.info("checkIDPProvider() fence_standard_access_rules        " + fence_standard_access_rules);
                logger.info("checkIDPProvider() fence_consent_group_concept_path   " + fence_parent_consent_group_concept_path);
                logger.info("checkIDPProvider() fence_harmonized_concept_path      " + fence_harmonized_concept_path);

                logger.debug("checkIDPProvider() idp provider OKTA is configured");
            } catch (Exception ex) {
                logger.error("checkIDPProvider() " + ex.getMessage());
                logger.error("checkIDPProvider() Invalid FENCE IDP Provider Setup. Mandatory fields are missing. " +
                        "Check configuration in standalone.xml");
            }
        } else if (idp_provider.equalsIgnoreCase("okta")) {
            try {
                idp_provider_uri = (String) ctx.lookup("java:global/idp_provider_uri");
                spClientSecret = (String) ctx.lookup("java:global/sp_client_secret");
                connectionId = (String) ctx.lookup("java:global/connection_id");
                clientId = (String) ctx.lookup("java:global/client_id");

                getFenceParentConsentGroupConceptPath(ctx);
                getFenceHarmonizaedGroupConsentPath(ctx);
                getFenceTopmedConsentGroupPath(ctx);
                getFenceStandardAccessRules(ctx);
                getFenceAllowedQueryTypes(ctx);
                getFenceHarmonizedConceptPath(ctx);

                logger.debug("checkIDPProvider() idp provider OKTA is configured");
            } catch (Exception ex) {
                logger.error("checkIDPProvider() " + ex.getMessage());
                logger.error("checkIDPProvider() Invalid OKTA IDP Provider Setup. Mandatory fields are missing. " +
                        "Check configuration in standalone.xml");
            }

        } else {
            logger.error("checkIDPProvider() Invalid IDP Provider Setup. Mandatory fields are missing. " +
                    "Check configuration in standalone.xml");
        }
        logger.debug("checkIDPProvider() finished");
    }

    private void getFenceTopmedConsentGroupPath(Context ctx) throws NamingException {
        fence_topmed_consent_group_concept_path = (String) ctx.lookup("java:global/fence_topmed_consent_group_concept_path");
        if (StringUtils.isBlank(fence_topmed_consent_group_concept_path)) {
            logger.error("checkIDPProvider() Empty topmed consent group concept path from standalone.xml. Using default!");
            fence_topmed_consent_group_concept_path = "\\\\_Consents\\\\Short Study Accession with Consent code\\\\";
        }
    }

    private void getFenceHarmonizaedGroupConsentPath(Context ctx) throws NamingException {
        fence_harmonized_consent_group_concept_path = (String) ctx.lookup("java:global/fence_harmonized_consent_group_concept_path");
        if (StringUtils.isBlank(fence_harmonized_consent_group_concept_path)) {
            logger.error("checkIDPProvider() Empty harmonized consent group concept path from standalone.xml. Using default!");
            fence_harmonized_consent_group_concept_path = "\\\\_Consents\\\\Short Study Accession with Consent code\\\\";
        }
    }

    private void getFenceStandardAccessRules(Context ctx) throws NamingException {
        fence_standard_access_rules = (String) ctx.lookup("java:global/fence_standard_access_rules");
        if (StringUtils.isBlank(fence_standard_access_rules)) {
            logger.error("checkIDPProvider() Missing Standard Access Rules in standalone.xml. Using defaults.");
            fence_standard_access_rules = "GATE_ONLY_INFO,GATE_ONLY_QUERY,GATE_ONLY_SEARCH,GATE_FENCE_CONSENT_REQUIRED";
        }
    }

    private void getFenceHarmonizedConceptPath(Context ctx) throws NamingException {
        fence_harmonized_concept_path = (String) ctx.lookup("java:global/fence_harmonized_concept_path");
        if (StringUtils.isBlank(fence_harmonized_concept_path)) {
            logger.error("checkIDPProvider() Empty harmonized concept path. Not in use.");
            fence_harmonized_concept_path = "";
        }
    }

    private void getFenceParentConsentGroupConceptPath(Context ctx) throws NamingException {
        fence_parent_consent_group_concept_path = (String) ctx.lookup("java:global/fence_parent_consent_group_concept_path");
        if (StringUtils.isBlank(fence_parent_consent_group_concept_path)) {
            logger.error("checkIDPProvider() Empty parent consent group concept path from standalone.xml. Using default!");
            fence_parent_consent_group_concept_path = "\\\\_Consents\\\\Short Study Accession with Consent code\\\\";
        }
    }

    private void getFenceAllowedQueryTypes(Context ctx) throws NamingException {
        fence_allowed_query_types = (String) ctx.lookup("java:global/fence_allowed_query_types");
        if (StringUtils.isBlank(fence_allowed_query_types)) {
            logger.error("checkIDPProvider() Missing Allowed query types from standalone.xml. Using defaults.");
            fence_allowed_query_types = "COUNT,CROSS_COUNT";
        }
    }

    private void initializeTokenExpirationTime(Context ctx) {
        try {
            tokenExpirationTime = Long.parseLong((String) ctx.lookup("java:global/tokenExpirationTime"));
        } catch (NamingException | ClassCastException | NumberFormatException ex) {
            tokenExpirationTime = defaultTokenExpirationTime;
        }

        logger.info("Set token expiration time to " + tokenExpirationTime + " milliseconds");

    }

    private void initializeLongTermTokenExpirationTime(Context ctx) {
        try {
            longTermTokenExpirationTime = Long.parseLong((String) ctx.lookup("java:global/longTermTokenExpirationTime"));
        } catch (NamingException | ClassCastException | NumberFormatException ex) {
            longTermTokenExpirationTime = defaultLongTermTokenExpirationTime;
        }

        logger.info("Set long term token expiration time to " + longTermTokenExpirationTime + " milliseconds");

    }

    private void initializeDefaultAdminRole() {

        // make sure system admin and super admin privileges are added in the database
        checkAndAddAdminPrivileges();

        if (checkIfAdminRoleExists()) {
            logger.info("Admin role already exists in database, no need for the creation.");
            return;
        }

        logger.info("Didn't find any role contains both " + ADMIN +
                " and " + SUPER_ADMIN +
                " in database, start to create one.");
        Privilege systemAdmin = privilegeRepo.getByColumn("name", ADMIN).get(0);
        Privilege superAdmin = privilegeRepo.getByColumn("name", SUPER_ADMIN).get(0);

        Role role = new Role();
        List<Role> roles = roleRepo.getByColumn("name", defaultAdminRoleName);
        boolean isAdminRole = false;
        if (roles != null && !roles.isEmpty()) {
            logger.info("Found a role with default admin name " + defaultAdminRoleName + ", but without proper privileges associated with");
            role = roles.get(0);
            isAdminRole = true;
        }
        role.setDescription("PIC-SURE Auth Micro App Top admin including Admin and super Admin");
        Set<Privilege> privileges = new HashSet<>();
        privileges.add(systemAdmin);
        privileges.add(superAdmin);
        role.setPrivileges(privileges);

        if (isAdminRole) {
            roleRepo.merge(role);
            logger.info("Finished updating the admin role, roleId: " + role.getUuid());
        } else {
            role.setName(defaultAdminRoleName);
            roleRepo.persist(role);
            logger.info("Finished creating an admin role, roleId: " + role.getUuid());
        }
    }

    private void checkAndAddAdminPrivileges() {
        logger.info("Checking if system admin and super admin privileges are added");
        List<Privilege> privileges = privilegeRepo.list();
        if (privileges == null)
            privileges = new ArrayList<>();

        Privilege superAdmin = null, systemAdmin = null;

        for (Privilege p : privileges) {
            if (superAdmin != null && systemAdmin != null)
                break;

            if (SUPER_ADMIN.equals(p.getName())) {
                superAdmin = p;
                continue;
            }

            if (ADMIN.equals(p.getName())) {
                systemAdmin = p;
                continue;
            }
        }

        if (superAdmin == null) {
            logger.info("Adding super admin");
            superAdmin = new Privilege();
            superAdmin.setName(SUPER_ADMIN);
            superAdmin.setDescription("PIC-SURE Auth super admin for managing roles/privileges/application/connections");
            privilegeRepo.persist(superAdmin);
        }

        if (systemAdmin == null) {
            logger.info("Adding system admin");
            systemAdmin = new Privilege();
            systemAdmin.setName(ADMIN);
            systemAdmin.setDescription("PIC-SURE Auth admin for managing users.");
            privilegeRepo.persist(systemAdmin);
        }
    }

    private boolean checkIfAdminRoleExists() {
        logger.info("Checking if admin role already exists in database");
        List<Role> roles = roleRepo.list();
        if (roles == null || roles.isEmpty()) {
            return false;
        }

        boolean systemAdmin = false, superAdmin = false;

        for (Role role : roles) {
            Set<Privilege> privileges = role.getPrivileges();
            if (privileges == null || privileges.isEmpty())
                continue;

            for (Privilege privilege : privileges) {
                if (ADMIN.equals(privilege.getName())) {
                    systemAdmin = true;
                } else if (SUPER_ADMIN.equals(privilege.getName())) {
                    superAdmin = true;
                }
            }
        }

        return systemAdmin && superAdmin;
    }

    public static String getPrincipalName(SecurityContext securityContext) {
        if (securityContext.getUserPrincipal() == null)
            return "No security context set, ";

        return securityContext.getUserPrincipal().getName();
    }

}
