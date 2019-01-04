package edu.harvard.hms.dbmi.avillach.auth.rest;

import com.fasterxml.jackson.databind.JsonNode;
import edu.harvard.dbmi.avillach.util.HttpClientUtil;
import edu.harvard.dbmi.avillach.util.PicsureNaming;
import edu.harvard.dbmi.avillach.util.Utilities;
import edu.harvard.dbmi.avillach.util.exception.ApplicationException;
import edu.harvard.dbmi.avillach.util.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration;
import edu.harvard.hms.dbmi.avillach.auth.data.entity.Application;
import edu.harvard.hms.dbmi.avillach.auth.data.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.data.repository.ApplicationRepository;
import edu.harvard.hms.dbmi.avillach.auth.data.repository.UserRepository;
import edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming;
import edu.harvard.hms.dbmi.avillach.auth.utils.AuthUtils;
import io.jsonwebtoken.*;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpResponse;
import org.apache.http.message.BasicHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Resource;
import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.persistence.NoResultException;
import javax.persistence.NonUniqueResultException;
import javax.ws.rs.*;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;


@Path("/token")
public class TokenService {

	private Logger logger = LoggerFactory.getLogger(TokenService.class);

//	@Resource(mappedName = "java:global/auth0token")
//	private String auth0token;
//
//	@Resource(mappedName = "java:global/auth0host")
//	private String auth0host;

	@Inject
	UserRepository userRepo;

	@Inject
	ApplicationRepository applicationRepo;

	@POST
	@RolesAllowed(AuthNaming.AuthRoleNaming.ROLE_TOKEN_INTROSPECTION)
	@Path("/inspect")
	@Consumes("application/json")
	public Response inspectToken(Map<String, String> tokenMap,
			@QueryParam(value = "applicationId") String applicationId){
		logger.info("TokenInspect starting...");
		TokenInspection tokenInspection = _inspectToken(tokenMap, applicationId);
		if (tokenInspection.message != null)
			tokenInspection.responseMap.put("message", tokenInspection.message);

		logger.info("Finished token introspection.");
		return PICSUREResponse.success(tokenInspection.responseMap);
	}

	private TokenInspection _inspectToken(Map<String, String> tokenMap, String applicationId){
		logger.debug("_inspectToken, the incoming token map is: " + tokenMap.entrySet()
		.stream()
		.map(entry -> entry.getKey() + " - " + entry.getValue())
		.collect(Collectors.joining(", ")) +" , application id is "
				+ applicationId);

		Application application = null;
		if (applicationId != null)
			application = applicationRepo.getById(UUID.fromString(applicationId));

		TokenInspection tokenInspection = new TokenInspection();

		String token = tokenMap.get("token");
		logger.debug("getting token: " + token);
		if (token == null || token.isEmpty()){
			logger.error("Token - "+ token + " is blank");
			tokenInspection.message = "Token not found";
			return tokenInspection;
		}

		// parse the token based on client secret
		// don't need to check if jws is null or not, since parse function has already checked
		Jws<Claims> jws;
		try {
			jws = AuthUtils.parseToken(JAXRSConfiguration.clientSecret, token);
		} catch (NotAuthorizedException ex) {
			tokenInspection.message = ex.getChallenges().toString();
			return tokenInspection;
		}

		String subject = jws.getBody().getSubject();

		// get the user based on subject field in token
		User user;
		try{
			user = userRepo.getByColumn("subject", subject).get(0);
			logger.info("_inspectToken() user with subject - " + subject + " - exists in database");
		} catch (NoResultException e) {
			logger.error("_inspectToken() could not find user with subject " + subject);
			tokenInspection.message = "error: user doesn't exist";
			return tokenInspection;
		}

		//Essentially we want to return jws.getBody() with an additional active: true field
		Set<String> privilegeNameSet = null;
		if (user != null
				&& user.getRoles() != null
				&& (privilegeNameSet = user.getPrivilegeNameSet()).contains(AuthNaming.AuthRoleNaming.ROLE_INTROSPECTION_USER))
			tokenInspection.responseMap.put("active", true);

		tokenInspection.responseMap.putAll(jws.getBody());

		// add all privileges into response based on application
		// if no application in request, return all privileges for now
		if (application != null) {
			tokenInspection.responseMap.put("privileges", user.getPrivilegeNameSetByApplication(application));
		} else {
			if (privilegeNameSet != null && !privilegeNameSet.isEmpty())
				tokenInspection.responseMap.put("privileges", privilegeNameSet);
		}

		logger.info("_inspectToken() Successfully inspect and return response map: "
				+ tokenInspection.responseMap.entrySet()
				.stream()
				.map(entry -> entry.getKey() + " - " + entry.getValue())
				.collect(Collectors.joining(", ")));
		return tokenInspection;
	}

//	private String getEmailForSubject(String subject) {
//		Map<String, String> researchMap = new HashMap<>();
//		researchMap.put("user_id", subject);
//		String email = null;
//		/**
//		 * now with a user, we can retrieve email info by subject from Auth0 and set to the user
//		 */
//		try {
//			email = getEmail(researchMap,
//					auth0host + "/api/v2/users",
//					auth0token);
//		} catch (IOException ex){
//			logger.error("IOException thrown when retrieving email from Auth0 server");
//		}
//
//		if (email==null || email.isEmpty()){
//			logger.error("Cannot retrieve email from auth0.");
//			return null;
//		} else {
//			return email;
//		}
//	}

	/**
	 * inner used token introspection class with active:false included
	 */
	private class TokenInspection {
		Map<String, Object> responseMap = new HashMap<>();
		String message = null;

		public TokenInspection() {
			responseMap.put("active", false);
		}
	}

	/**
	 * This method is retrieving email from Auth0 by any specific fields.
	 * Now we only support Auth0 search. If in the future, we want to support
	 * other search methods, it is better to create an interface.
	 *
	 * @return
	 */
	private String getEmail(Map<String, String> searchMap, String auth0host, String token)
			throws IOException {
		String email = null;

		String searchString = "";
		for (Map.Entry<String, String> entry : searchMap.entrySet()){
			searchString += URLEncoder.encode(entry.getKey() +":" + entry.getValue(), "utf-8") + "%20or%20";
		}

		if (searchString.isEmpty()) {
			logger.error("getEmail() no searchString generated." );
			return null;
		}

		searchString = searchString.substring(0, searchString.length()-8);

		String requestPath = "?fields=email&include_fields=true&q=" + searchString;

		String uri = auth0host + requestPath;

		org.apache.http.Header[] headers = new org.apache.http.Header[]{new BasicHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token)};
		HttpResponse response = HttpClientUtil.retrieveGetResponse(uri, headers);


		if (response.getStatusLine().getStatusCode() != 200) {
			logger.error(uri + " did not return a 200: {} {}",response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase());
			//If the result is empty, a 500 is thrown for some reason
			JsonNode responseObject = JAXRSConfiguration.objectMapper.readTree(response.getEntity().getContent());

			if (response.getStatusLine().getStatusCode() == 401) {
				logger.error("Communicating with Auth0 get a 401: " + responseObject + " with URI: " + uri);
			}
			logger.error("Error when communicating with Auth0 server" + responseObject + " with URI: " + uri);
			throw new ApplicationException("Inner application error, please contact admin.");
		}

		JsonNode responseJson = JAXRSConfiguration.objectMapper.readTree(response.getEntity().getContent());

		logger.debug("getEmail() response from Auth0 " + JAXRSConfiguration.objectMapper.writeValueAsString(responseJson));

		if (responseJson.isArray() && responseJson.get(0) != null){
			email = responseJson.get(0).get("email").textValue();
		} else {
			logger.error("getEmail() response from Auth0 is not returning an json array");
		}

		return email;
	}

}
