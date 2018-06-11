package io.gravitee.policy.uma;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.AuthorizationResponse;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.keycloak.util.JsonSerialization;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UMAHelper {
	
//	private final static Logger logger = LoggerFactory.getLogger(UMAHelper.class);
//
//    public static List<Permission> authorize(String resource, String token, String[] scopes, AuthzClient client) throws Exception {
//		if ( resource == null || resource.equals("")) return new ArrayList<Permission>();
//		
//		AuthorizationRequest authorizationRequest = new AuthorizationRequest();
//		
//		logger.debug("create auth request");
//		
////		AccessTokenResponse atr = client.obtainAccessToken("admin", "admin");	 //why the source token is not valid????
////		token = atr.getToken();
//		
//		authorizationRequest.setAccessToken(token);
//		
//		logger.debug("added token: " + token);
//		
//		authorizationRequest.addPermission( resource, scopes );
//		
//		logger.debug("request access for resource: " + resource + " with scopes " + Arrays.toString(scopes));
//		
//		AuthorizationResponse response = client.authorization(token).authorize(authorizationRequest);
//		
//		logger.debug(response.toString());
//	
//		AccessToken at = toAccessToken(response.getToken());
//		
//		logger.debug(at.toString());
//		
//		AccessToken.Authorization authorization = at.getAuthorization();
//		
//		logger.debug( authorization.toString());
//		
//        return authorization.getPermissions();
//	}
//    
//    public static List<Permission> authorize(ResourceRepresentation resource, String token, String[] scopes, AuthzClient client) throws Exception {
//		if ( resource == null ) return new ArrayList<Permission>();
//		return authorize(resource.getId(), token, scopes, client);
//	}
//    
//    
//    public static List<Permission> authorize(String[] resources, String token, String[] scopes, AuthzClient client) throws Exception {
//		if (resources.length == 0) return new ArrayList<Permission>();
//		
//		AuthorizationRequest authorizationRequest = new AuthorizationRequest();
//		
//		logger.debug("create auth request");
//		
//		authorizationRequest.setAccessToken(token);
//		
////		AccessTokenResponse atr = client.obtainAccessToken("admin", "admin");	 //why the source token is not valid????
////		token = atr.getToken();
//		
//		logger.debug("added token: " + token);
//		
//		Arrays.asList(resources).forEach( resourceId -> {
//			authorizationRequest.addPermission( resourceId, scopes );
//			logger.debug("request access for resource: " + resourceId + " with scopes " + Arrays.toString(scopes));
//		});
//		
//		AuthorizationResponse response = client.authorization(token).authorize(authorizationRequest);
//		
//		logger.debug(response.toString());
//	
//		AccessToken at = toAccessToken(response.getToken());
//		
//		logger.debug(at.toString());
//		
//		AccessToken.Authorization authorization = at.getAuthorization();
//		
//		logger.debug( authorization.toString());
//		
//        return authorization.getPermissions();
//	}
//	
//	public static List<Permission> authorize(List<ResourceRepresentation> resources, String token, String[] scopes, AuthzClient client) throws Exception {
//		List<String> resourceIds = resources.stream().map( n -> n.getId() ).collect(Collectors.toList());
//		return authorize(resourceIds.toArray(new String[]{}), token, scopes, client);
//	}
//	
//	public static List<Permission> authorize(String token, AuthzClient client) throws Exception {
//		AuthorizationRequest authorizationRequest = new AuthorizationRequest();
//		
//		logger.debug("create auth request");
//		
////		AccessTokenResponse atr = client.obtainAccessToken("admin", "admin");	 //why the source token is not valid????
////		token = atr.getToken();
////		
//		authorizationRequest.setAccessToken(token);
//		
//		logger.debug("added token: " + token);
//			
//		AuthorizationResponse response = client.authorization(token).authorize(authorizationRequest);
//	
//		AccessToken at = toAccessToken(response.getToken());
//		
//		AccessToken.Authorization authorization = at.getAuthorization();
//		
//        return authorization.getPermissions();
//	}
	
//	public static Set<ScopeRepresentation> getScopeRepresentationSet(String[] scopes){
//		Set<ScopeRepresentation> scopeSet = new HashSet<ScopeRepresentation>();
//		for (String scope: scopes)         
//			scopeSet.add(getScopeRepresentation(scope));
//		return scopeSet;
//	}
//	
//	public static ScopeRepresentation getScopeRepresentation(String scope) {
//		ScopeRepresentation sr = new ScopeRepresentation();
//		sr.setName(scope);
//		return sr;
//	}
//	
//
//	
//    public static AccessToken toAccessToken(String rpt) throws Exception {
//        return JsonSerialization.readValue(new JWSInput(rpt).getContent(), AccessToken.class);
//    }
	
}
