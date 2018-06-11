/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.uma;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.jayway.jsonpath.JsonPath;
import com.mifmif.common.regex.Generex;

import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.HttpMethod;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.common.http.MediaType;
import io.gravitee.common.util.MultiValueMap;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.gateway.api.http.stream.TransformableRequestStreamBuilder;
import io.gravitee.gateway.api.http.stream.TransformableResponseStreamBuilder;
import io.gravitee.gateway.api.stream.ReadWriteStream;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.api.annotations.OnRequestContent;
import io.gravitee.policy.api.annotations.OnResponse;
import io.gravitee.policy.api.annotations.OnResponseContent;
import io.gravitee.policy.uma.configuration.UMAPolicyConfiguration;
import io.gravitee.resource.api.ResourceManager;
import io.gravitee.resource.oauth2.api.OAuth2Response;
import io.gravitee.resource.uma2.keycloak.Uma2KeycloakResource;
import net.minidev.json.JSONArray;

import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.util.JsonSerialization;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.security.Policy.Parameters;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
public class UMAPolicy {

    private final Logger logger = LoggerFactory.getLogger(UMAPolicy.class);

    static final String BEARER_AUTHORIZATION_TYPE = "Bearer";
    static final String HEADER_TENANT_PARAMETER = "Fiware-Service";
    static final String OAUTH_PAYLOAD_SCOPE_NODE = "scope";
    static final String OAUTH_PAYLOAD_RPT_NODE = "access_token";
    static final String OAUTH_PAYLOAD_CLIENT_ID_NODE = "client_id";
    static final String OAUTH_PAYLOAD_USER_ID_NODE = "$.sub";

    static final String CONTEXT_ATTRIBUTE_PREFIX = "uma.";
    static final String CONTEXT_ATTRIBUTE_OAUTH_PAYLOAD = CONTEXT_ATTRIBUTE_PREFIX + "payload";
    static final String CONTEXT_ATTRIBUTE_OAUTH_ACCESS_TOKEN = CONTEXT_ATTRIBUTE_PREFIX + "access_token";
    static final String CONTEXT_ATTRIBUTE_CLIENT_ID = CONTEXT_ATTRIBUTE_PREFIX + "client_id";
    static final String CONTEXT_ATTRIBUTE_RPT = CONTEXT_ATTRIBUTE_PREFIX + "rpt";
    static final String CONTEXT_ATTRIBUTE_RESOURCE_ID = CONTEXT_ATTRIBUTE_PREFIX + "resource_id";
    static final String CONTEXT_ATTRIBUTE_AUTHCLIENT = CONTEXT_ATTRIBUTE_PREFIX + "authClient";   
    static final String CONTEXT_ATTRIBUTE_ATTRIBUTE_VALUES = CONTEXT_ATTRIBUTE_PREFIX + "attrValues"; 
    static final String CONTEXT_ATTRIBUTE_ALL_QUERY = CONTEXT_ATTRIBUTE_PREFIX + "allQuery"; 
    static final String CONTEXT_ATTRIBUTE_PERMISSIONS = CONTEXT_ATTRIBUTE_PREFIX + "permissions"; 
    static final String CONTEXT_ATTRIBUTE_TENANT = CONTEXT_ATTRIBUTE_PREFIX + "tenant"; 
    
    public static final String RESOURCEID_REQUEST_BODY = "REQUEST_BODY";
    public static final String RESOURCEID_RESPONSE_BODY = "RESPONSE_BODY";
    public static final String RESOURCEID_QUERY = "QUERY";
    public static final String RESOURCEID_PATH = "PATH";
    

    static final ObjectMapper MAPPER = new ObjectMapper();

    private UMAPolicyConfiguration umaPolicyConfiguration;

    public UMAPolicy (UMAPolicyConfiguration umaPolicyConfiguration) throws IOException {
        this.umaPolicyConfiguration = umaPolicyConfiguration;
        logger.debug("instance created");
    }
    
    @OnRequest
    public void onRequest(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) {
        logger.debug("Read access_token from request {}", request.id());

        Uma2KeycloakResource oauth2 = executionContext.getComponent(ResourceManager.class).getResource(
                umaPolicyConfiguration.getOauthResource(), Uma2KeycloakResource.class);

        if (oauth2 == null) {
            policyChain.failWith(PolicyResult.failure(HttpStatusCode.UNAUTHORIZED_401,
                    "No OAuth authorization server has been configured"));
            return;
        }

        List<String> authorizationHeaders = request.headers().get(HttpHeaders.AUTHORIZATION);

        if (authorizationHeaders == null || authorizationHeaders.isEmpty()) {
            sendError(response, policyChain, "invalid_request", "No OAuth authorization header was supplied");
            return;
        }

        Optional<String> optionalHeaderAccessToken = authorizationHeaders
                .stream()
                .filter(h -> StringUtils.startsWithIgnoreCase(h, BEARER_AUTHORIZATION_TYPE))
                .findFirst();
        if (!optionalHeaderAccessToken.isPresent()) {
            sendError(response, policyChain, "invalid_request", "No OAuth authorization header was supplied");
            return;
        }

        String accessToken = optionalHeaderAccessToken.get().substring(BEARER_AUTHORIZATION_TYPE.length()).trim();
        if (accessToken.isEmpty()) {
            sendError(response, policyChain, "invalid_request", "No OAuth access token was supplied");
            return;
        }

        // Set access_token in context
        executionContext.setAttribute(CONTEXT_ATTRIBUTE_OAUTH_ACCESS_TOKEN, accessToken);
        
        
        String tenant = request.headers().getFirst(HEADER_TENANT_PARAMETER);
        
        if (tenant == null)
        		tenant = Uma2KeycloakResource.DEFAULT_TENANT;
        
        executionContext.setAttribute(CONTEXT_ATTRIBUTE_TENANT, tenant);

        // Validate access token
        logger.debug(" access token: "+ accessToken);
       
        String resourceId = extractResourceIdFromRequest(request);
        
        executionContext.setAttribute(CONTEXT_ATTRIBUTE_RESOURCE_ID, resourceId);
        
        String[] resources = null;
        
        boolean allQuery = false;
        
        String baseAppPath = (String) executionContext.getAttribute("gravitee.attribute.resolved-path");
        
        if ( Uma2KeycloakResource.createURI(baseAppPath,"").equals(Uma2KeycloakResource.createURI(request.pathInfo(), "")))
        		allQuery = true;
        
        executionContext.setAttribute(CONTEXT_ATTRIBUTE_ALL_QUERY, allQuery);
        
        if (request.method().equals(HttpMethod.GET) && allQuery) {
        		//retrieve all resources
    			resources = oauth2.findMatchingResource(createRegex("(.*)"), tenant, false).stream().map( resource -> {
    				return resource.getId();
    			}).collect(Collectors.toSet()).toArray(new String[] {});
        } else if ((!allQuery || resourceId != null) && !request.method().equals(HttpMethod.POST)) {
        			String uri = request.pathInfo();
        			if ( resourceId != null ) uri = createBaseUriFromPattern(resourceId, request.method());
        			resources = oauth2.findMatchingResource(uri, tenant, true).stream().map( resource -> {
        				return resource.getId();
        			}).collect(Collectors.toSet()).toArray(new String[] {});
        			if(resources.length > 0)
        				resources = new String[] {resources[0]};
        } else if ( request.method().equals(HttpMethod.POST) && allQuery ) {
    			logger.debug(" resource creation ");
			resources = oauth2.findMatchingResource(createBaseUriFromPattern("{id}"), tenant, true).stream().map( resource -> {
    				return resource.getId();
    			}).collect(Collectors.toSet()).toArray(new String[] {});
			if(resources.length > 0)
    				resources = new String[] {resources[0]};
		} else {
			sendError(response, policyChain, "invalid_request", "invalid or missing resource id");
			return;
		}
        
        if(resources.length == 0) {
			policyChain.failWith(PolicyResult.failure(HttpStatusCode.NOT_FOUND_404,
					"The resource selected is not available or not indexed"));
			return;
		}
        String[] permissions = createAuthorizationResource(accessToken, resources, request.method());
        
        String client_id;
		try {
			client_id = toAccessToken(accessToken).getIssuedFor();
		} catch (Exception e) {
			sendError(response, policyChain, "invalid_request", "no valid client could be found");
			return;
		}
        
        // Validate access token
        oauth2.authorizeUma(accessToken, permissions, client_id, handleUmaAuthResponse(policyChain, request, response, executionContext));
    }

    String createRegex(String resourceId, HttpMethod method) {
    		String pattern = createBaseUriFromPattern(resourceId, method);
    		pattern = pattern.replace("/", "\\/");
    		pattern = pattern.replace("?", "\\?");
    		return pattern;
    }
    
    String createRegex(String resourceId) {
		return createRegex(resourceId, HttpMethod.GET);
    }
    
    String createBaseUriFromPattern(String resourceId) {
	    return createBaseUriFromPattern(resourceId, HttpMethod.GET);
    }
    
    String createBaseUriFromPattern(String resourceId, HttpMethod method) {
		String extractorType = umaPolicyConfiguration.getExtractResourceID(method);
		String pattern =  umaPolicyConfiguration.getResourceIDPattern(extractorType);
	    	Generex generex = new Generex(pattern);
	    	String baseUri = generex.random();
	    return replaceGroup(pattern,baseUri,1,resourceId);
    }
    
    public static String replaceGroup(String regex, String source, int groupToReplace, String replacement) {
        return replaceGroup(regex, source, groupToReplace, 1, replacement);
    }

    public static String replaceGroup(String regex, String source, int groupToReplace, int groupOccurrence, String replacement) {
        Matcher m = Pattern.compile(regex).matcher(source);
        for (int i = 0; i < groupOccurrence; i++)
            if (!m.find()) return source; // pattern not met, may also throw an exception here
        return new StringBuilder(source).replace(m.start(groupToReplace), m.end(groupToReplace), replacement).toString();
    }
    
    
	@OnResponse
	public void onResponse(Request request, Response response, ExecutionContext executionContext,
			PolicyChain policyChain) {
		try {
			Uma2KeycloakResource oauth2 = executionContext.getComponent(ResourceManager.class).getResource(
					umaPolicyConfiguration.getOauthResource(), Uma2KeycloakResource.class);
			policyChain.doNext(request, response);
			if (isASuccessfulResponse(response)) {
				logger.debug("successful response from the server");
				boolean allQuery = (boolean) executionContext.getAttribute(CONTEXT_ATTRIBUTE_ALL_QUERY);
				String localId = getResourceId(executionContext);
				String tenant = (String) executionContext.getAttribute(CONTEXT_ATTRIBUTE_TENANT);
				String ownerId = getOwnerId((String) executionContext.getAttribute(CONTEXT_ATTRIBUTE_OAUTH_ACCESS_TOKEN));
				logger.debug(
						"owner " + ownerId);
				if (request.method().equals(HttpMethod.POST) && umaPolicyConfiguration.getCreateOnResponse() && allQuery)
					oauth2.createResource(tenant, localId,
							ownerId,
							createBaseUriFromPattern(getResourceId(executionContext)),
							umaPolicyConfiguration.getResourceType(),
							umaPolicyConfiguration.getResourceScopes().toArray(new String[] {}),
							true);
				if (request.method().equals(HttpMethod.POST) && umaPolicyConfiguration.getCreateOnResponse() && umaPolicyConfiguration.getIncludeSubPath() && allQuery)
					oauth2.createResource(tenant, localId+"/*",
							ownerId,
							createBaseUriFromPattern(getResourceId(executionContext)+"*"),
							umaPolicyConfiguration.getResourceType(),
							umaPolicyConfiguration.getResourceScopes().toArray(new String[] {}),
							true);
				if ((request.method().equals(HttpMethod.POST) || request.method().equals(HttpMethod.PUT)) && umaPolicyConfiguration.getCreateOnResponse() && umaPolicyConfiguration.getIncludeJsonAttributes() != null && !umaPolicyConfiguration.getIncludeJsonAttributes().equals("")) {
					//for each attribute matching the patter, create an entry
    	    				List<Entry<String, JsonNode>> attributes = (List<Entry<String, JsonNode>>) executionContext.getAttribute(CONTEXT_ATTRIBUTE_ATTRIBUTE_VALUES);
    	    				attributes.stream().forEach((Entry<String, JsonNode> e) -> {
    	    					//if specific path, the entry will be created on such path
    	    					String id = Uma2KeycloakResource.createURI(localId,e.getKey());
    	    					String path = null;
    	    					if (umaPolicyConfiguration.getIncludeJsonAttrBaseURI()!=null && !umaPolicyConfiguration.getIncludeJsonAttrBaseURI().equals(""))
    	    						path = Uma2KeycloakResource.createURI(umaPolicyConfiguration.getIncludeJsonAttrBaseURI(), id);
    	    					else 
    	    						path = Uma2KeycloakResource.createURI(request.pathInfo(), Uma2KeycloakResource.createURI(localId, "attrs/" + e.getKey()) );
    	    					String type = null;
    	    					if (umaPolicyConfiguration.getResourceTypeAttr() != null && !umaPolicyConfiguration.getResourceTypeAttr().equals(""))
    	    						type = umaPolicyConfiguration.getResourceTypeAttr();
    	    					else
    	    						type = umaPolicyConfiguration.getResourceType();
    	    					oauth2.createResource(tenant, id,
    	    							ownerId,
    	    							path,
    	    							type,
    	    							umaPolicyConfiguration.getResourceScopes().toArray(new String[] {}),
    	    							true);
    	    				});

				}
				String accessToken = (String) executionContext.getAttribute(CONTEXT_ATTRIBUTE_OAUTH_ACCESS_TOKEN);
				
				List<Permission> permissions = (List<Permission>) executionContext.getAttribute(CONTEXT_ATTRIBUTE_PERMISSIONS);
				if (permissions != null && !permissions.isEmpty())
					permissions.forEach( permission -> oauth2.audit(accessToken, permission.getResourceId(), handleAuditResponse()) );
				if (umaPolicyConfiguration.getDeleteOnResponse() && request.method().equals(HttpMethod.DELETE))
					oauth2.deleteResource(createBaseUriFromPattern(getResourceId(executionContext), HttpMethod.DELETE),tenant);

			}
			return;
		} catch (Exception e) {
			logger.debug(e.getMessage());
			e.printStackTrace();
		}
    }
    
    private static boolean isASuccessfulResponse(Response response) {
        switch (response.status() / 100) {
            case 1:
            case 2:
            case 3:
                return true;
            default:
                return false;
        }
    }
    
    @OnResponseContent
    public ReadWriteStream onResponseContent(Request request, Response response, ExecutionContext executionContext,
            PolicyChain policyChain) {
            return TransformableResponseStreamBuilder
                    .on(response)
                    .chain(policyChain)
                    .transform(map(true,request, response, executionContext))
                    .build();
    }

    @OnRequestContent
    public ReadWriteStream onRequestContent(Request request, Response response, ExecutionContext executionContext,
            PolicyChain policyChain) {
            return TransformableRequestStreamBuilder
                    .on(request)
                    .chain(policyChain)
                    .transform(map(false,request, response, executionContext))
                    .build();
    }

    Function<Buffer, Buffer> map(boolean onresponse, Request request, Response response, ExecutionContext executionContext) {
        return input -> {
        		String extractorType = umaPolicyConfiguration.getExtractResourceID(request.method());
        		boolean allQuery = (boolean) executionContext.getAttribute(CONTEXT_ATTRIBUTE_ALL_QUERY);
        		if (extractorType!=null && allQuery && ((extractorType.equals(RESOURCEID_RESPONSE_BODY) && onresponse) ||
        				(extractorType.equals(RESOURCEID_REQUEST_BODY)  && !onresponse))) {
        			String pattern = umaPolicyConfiguration.getResourceIDPattern(extractorType);
            		String id = null;
	    	    		try {
	    	    			id = getResourceIdFromJson(input.toString(), pattern);
	    	    		} catch (Exception e) {
	    	    			e.printStackTrace();
	    	    		}
            		logger.debug("id: " + id + " extracted from " +input.toString());
            	    if (id !=null && !id.equals("")) executionContext.setAttribute(CONTEXT_ATTRIBUTE_RESOURCE_ID, id);
        		}
        	    if (!onresponse && (request.method().equals(HttpMethod.POST) || request.method().equals(HttpMethod.PUT)) && umaPolicyConfiguration.getCreateOnResponse() && umaPolicyConfiguration.getIncludeJsonAttributes() != null) {
        	    		List<Entry<String, JsonNode>> attributes = getAttributesFromJson(input.toString(), umaPolicyConfiguration.getIncludeJsonAttributes());
        	    		executionContext.setAttribute(CONTEXT_ATTRIBUTE_ATTRIBUTE_VALUES, attributes);
        	    }
        	    if (onresponse && request.method().equals(HttpMethod.GET) && umaPolicyConfiguration.getAllFilterOnResponse() && allQuery) {
        	    		List<Permission> permissions = (List<Permission>) executionContext.getAttribute(CONTEXT_ATTRIBUTE_PERMISSIONS);
        	    		String pattern = umaPolicyConfiguration.getResourceIDPattern(extractorType);
        	        Uma2KeycloakResource oauth2 = executionContext.getComponent(ResourceManager.class).getResource(
        	                    umaPolicyConfiguration.getOauthResource(), Uma2KeycloakResource.class);
				String jsonQuery = null;
				try {
					jsonQuery = umaPolicyConfiguration.getRootFilterOnResponse() + "[?(";
					for (Iterator<Permission> iterator = permissions.iterator(); iterator.hasNext();) {
						Permission perm = iterator.next();
						ResourceRepresentation resource = oauth2.findResource(perm.getResourceId());
						String id = getResourceIdFromPlainText(resource.getUri(), pattern);

						if (id != null && !id.equals(""))
							jsonQuery += umaPolicyConfiguration.getObjectFilterOnResponse() + "==\"" + id + "\"";
						if (id != null && !id.equals("") & iterator.hasNext())
							jsonQuery += " || ";
					}
					jsonQuery += ")]";
				} catch (Exception e) {
					e.printStackTrace();
				}
				Buffer bodyBuffer = Buffer.buffer();
				try {
					JSONArray result = JsonPath.read(input.toString(), jsonQuery);
					bodyBuffer.appendString(result.toJSONString());
				} catch (Exception e) {
					bodyBuffer.appendString("[]");
				}
				return bodyBuffer;
			}
			return input;
		};
    }
    
    String getResourceId(ExecutionContext executionContext){
    		return (String) executionContext.getAttribute(CONTEXT_ATTRIBUTE_RESOURCE_ID);
    }
    
    String[] createAuthorizationResource(String accessToken, String resource, HttpMethod method){
    		logger.debug(" create authorization request for a specific resource");
    		Set<String> permissions = new HashSet<>();
    		if (umaPolicyConfiguration.getResourceScopeMethod(method).length > 0)
    			for(String scope: umaPolicyConfiguration.getResourceScopeMethod(method))
    				permissions.add(resource+"#"+scope);
    		else permissions.add(resource);
    		return permissions.toArray(new String[] {});
    }
    
    String[] createAuthorizationResource(String accessToken, String[] resources, HttpMethod method){
    		logger.debug(" create authorization request for set of resources");
		Set<String> permissions = new HashSet<>();
		for (String resource: resources) {
			if (umaPolicyConfiguration.getResourceScopeMethod(method).length > 0)
				for(String scope: umaPolicyConfiguration.getResourceScopeMethod(method))
					permissions.add(resource+"#"+scope);
			else permissions.add(resource);
		}
		return permissions.toArray(new String[] {});
    }
    
    AccessToken toAccessToken(String rpt) throws Exception {
        return JsonSerialization.readValue(new JWSInput(rpt).getContent(), AccessToken.class);
    }
	
	private void logPermission(List<Permission> permissions){
		permissions.forEach( p ->{
			logger.debug("resource: "+p.getResourceName() + " scopes: " + p.getScopes());
		});
	}
    
    String extractResourceIdFromRequest(Request request) {
		logger.debug(request.pathInfo());
		logger.debug(request.contextPath());
		logger.debug(request.path());
		logger.debug(request.id());
		logger.debug(request.uri()); // from here we can extract query

		String extractorType = umaPolicyConfiguration.getExtractResourceID(request.method());
		String pattern = umaPolicyConfiguration.getResourceIDPattern(extractorType);
		
		String id = null;
		
    		if(extractorType.equals(RESOURCEID_QUERY)) {
    			String query = getQuery(request);
    			if (getResourceIdFromPlainText(query, pattern) != null && !getResourceIdFromPlainText(query, pattern).equals(""))
    				id = getResourceIdFromPlainText(query, pattern);
    		} else if(extractorType.equals(RESOURCEID_PATH)) {
    			if (getResourceIdFromPlainText(request.pathInfo(), pattern) != null && !getResourceIdFromPlainText(request.pathInfo(), pattern).equals(""))
    				id = getResourceIdFromPlainText(request.pathInfo(), pattern);
    		}
    		return id;
    }
    
    String getQuery(Request request) {
    		MultiValueMap<String, String> parameters = request.parameters();
    		String query = "";
    		for ( Iterator<Entry<String, List<String>>> it = parameters.entrySet().iterator(); it.hasNext();) {
    			Entry <String, List<String>> entry = it.next();
    			query += entry.getKey()+"=";
    			List<String> values = entry.getValue();
    			for ( Iterator<String> it2 = values.iterator(); it2.hasNext(); ) {
    				String value = it2.next();
    				query += value;
    				if (it2.hasNext())
    					query += ",";
    			}
    			if (it.hasNext())
    				query += "&";
    		}
    		return request.pathInfo()+"?"+query;
    }
    
    String getResourceIdFromPlainText(String path, String regex) {
    	    Pattern p = Pattern.compile(regex);
    	    Matcher m = p.matcher(path);
    	    if(m.find()) {
    	    		String group = m.group(1);
    	    		logger.debug(" found match: " + group + " for regex [" + regex + "] on path ["+ path +"]");
    	    		return group;
    	    }
    	    logger.debug("no match");
    	    return null;
    }
    
    String getResourceIdFromJson(String json, String query) {
    		return JsonPath.read(json, query);
    }
    
    List<Entry<String, JsonNode>> getAttributesFromJson(String json, String query) {
    		JsonNode oauthResponseNode = readPayload(json);
    		List<Entry<String, JsonNode>> result = new ArrayList<>();
    		for (Iterator<Entry<String, JsonNode>> iterator = oauthResponseNode.fields(); iterator.hasNext(); ) {
    			Entry<String, JsonNode> entry = iterator.next();
    			Pattern p = Pattern.compile(query);
        	    Matcher m = p.matcher(entry.getKey());
        	    if(m.find())
        	    		result.add(entry);
    		}
    		return result;
    }
    
    String getOwnerId(String token) throws Exception {
    		return toAccessToken(token).getSubject();
    }
    
    Handler<OAuth2Response> handleAuditResponse() {
        return oauth2response -> {
            if (oauth2response.isSuccess()) {
            		logger.debug("audit worked");
            }
        };
    }

    Handler<OAuth2Response> handleUmaAuthResponse(PolicyChain policyChain, Request request, Response response, ExecutionContext executionContext) {
        return oauth2response -> {
            if (oauth2response.isSuccess()) {
                JsonNode oauthResponseNode = readPayload(oauth2response.getPayload());

                if (oauthResponseNode == null) {
                    sendError(response, policyChain, "server_error", "Invalid response from authorization server");
                    return;
                }

                // Extract client_id
                String rpt = oauthResponseNode.path(OAUTH_PAYLOAD_RPT_NODE).asText();
                if (rpt != null && !rpt.trim().isEmpty()) {
                    executionContext.setAttribute(CONTEXT_ATTRIBUTE_RPT, rpt);
                }

                try {
					AccessToken at = toAccessToken(rpt);
					
					List<Permission> permissions = at.getAuthorization().getPermissions();
					String resourceId = getResourceId(executionContext);
					 
			        logPermission(permissions);
					if (permissions.isEmpty()) {
						sendError(response, policyChain, "access_denied", "not_authorized");
						return;
					}
					
					executionContext.setAttribute(CONTEXT_ATTRIBUTE_PERMISSIONS, permissions);
					boolean allQuery = (boolean) executionContext.getAttribute(CONTEXT_ATTRIBUTE_ALL_QUERY);
					
					if (request.method().equals(HttpMethod.GET) && allQuery && umaPolicyConfiguration.getAppendResourceFilter() != null && !umaPolicyConfiguration.getAppendResourceFilter().equals("")) {
						// attach list of authorised resources to the path
						String filter = umaPolicyConfiguration.getAppendResourceFilter();
						if (filter == null || filter.equals("") )
							filter = "id";
						Set<String> ids = permissions.stream().map( permission -> retrievePathId(permission.getResourceId(), executionContext)).collect(Collectors.toSet());
						Set<String> requestedIds = null;
						if (request.parameters().get(filter) != null)
							requestedIds = request.parameters().get(filter).stream().collect(Collectors.toSet());
						if (requestedIds !=null && !requestedIds.isEmpty())
							ids.retainAll(requestedIds);
						if (ids.isEmpty()) {
							sendError(response, policyChain, "not_authorized", "the requested set of IDs is not included in the authorised ones");
							return;
						}
							
						String value = String.join(",", ids);
						logger.debug(" allowed ids:" +ids);
						request.parameters().add(filter, value);
					}	
					
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
					policyChain.failWith(PolicyResult.failure(HttpStatusCode.UNAUTHORIZED_401,
                            oauth2response.getPayload(), MediaType.APPLICATION_JSON));
					return;
				} 

                // Continue chaining
                policyChain.doNext(request, response);
            } else {
                response.headers().add(HttpHeaders.WWW_AUTHENTICATE, BEARER_AUTHORIZATION_TYPE + " realm=gravitee.io ");

                if (oauth2response.getThrowable() == null) {
                    policyChain.failWith(PolicyResult.failure(HttpStatusCode.UNAUTHORIZED_401,
                            oauth2response.getPayload(), MediaType.APPLICATION_JSON));
                    return;
                } else {
                    policyChain.failWith(PolicyResult.failure(HttpStatusCode.SERVICE_UNAVAILABLE_503,
                            "temporarily_unavailable"));
                    return;
                }
            }
        };
    }
    
    String retrievePathId(String id, ExecutionContext executionContext) {
		String extractorType = umaPolicyConfiguration.getExtractResourceID(HttpMethod.GET);
		String pattern = umaPolicyConfiguration.getResourceIDPattern(extractorType);
    		Uma2KeycloakResource oauth2 = executionContext.getComponent(ResourceManager.class).getResource(
                umaPolicyConfiguration.getOauthResource(), Uma2KeycloakResource.class);
    			ResourceRepresentation resource;
				try {
					resource = oauth2.findResource(id);
					return getResourceIdFromPlainText(resource.getUri(), pattern);    
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			return null;    	
    }
    
    
    /**
     * As per https://tools.ietf.org/html/rfc6750#page-7:
     *
     *      HTTP/1.1 401 Unauthorized
     *      WWW-Authenticate: Bearer realm="example",
     *      error="invalid_token",
     *      error_description="The access token expired"
     */
    private void sendError(Response response, PolicyChain policyChain, String error, String description) {
        String headerValue = BEARER_AUTHORIZATION_TYPE +
                " realm=\"gravitee.io\"," +
                " error=\"" + error + "\"," +
                " error_description=\"" + description + "\"";
        response.headers().add(HttpHeaders.WWW_AUTHENTICATE, headerValue);
        policyChain.failWith(PolicyResult.failure(HttpStatusCode.UNAUTHORIZED_401, null));
    }

    private JsonNode readPayload(String oauthPayload) {
        try {
            return MAPPER.readTree(oauthPayload);
        } catch (IOException ioe) {
            logger.error("Unable to check required scope from introspection endpoint payload: {}", oauthPayload);
            return null;
        }
    }

    static boolean hasRequiredScopes(JsonNode oauthResponseNode, List<String> requiredScopes, String scopeSeparator) {
        if (requiredScopes == null) {
            return true;
        }

        JsonNode scopesNode = oauthResponseNode.path(OAUTH_PAYLOAD_SCOPE_NODE);

        List<String> scopes;
        if (scopesNode instanceof ArrayNode) {
            Iterator<JsonNode> scopeIterator = scopesNode.elements();
            scopes = new ArrayList<>(scopesNode.size());
            List<String> finalScopes = scopes;
            scopeIterator.forEachRemaining(jsonNode -> finalScopes.add(jsonNode.asText()));
        } else {
            scopes = Arrays.asList(scopesNode.asText().split(scopeSeparator));
        }

        return scopes.containsAll(requiredScopes);
    }
}
