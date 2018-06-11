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
import com.jayway.jsonpath.JsonPath;
import com.mifmif.common.regex.Generex;

import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.HttpMethod;
import io.gravitee.common.util.LinkedMultiValueMap;
import io.gravitee.common.util.MultiValueMap;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.uma.UMAPolicy;
import io.gravitee.policy.uma.configuration.UMAPolicyConfiguration;
import io.gravitee.resource.api.ResourceConfiguration;
import io.gravitee.resource.api.ResourceManager;
import io.gravitee.resource.oauth2.api.OAuth2Resource;
import io.gravitee.resource.oauth2.api.OAuth2Response;
import io.gravitee.resource.uma2.keycloak.Uma2KeycloakResource;
import io.gravitee.resource.uma2.keycloak.configuration.Uma2KeycloakResourceConfiguration;
import net.minidev.json.JSONArray;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.util.JsonSerialization;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.UUID;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;
import static org.mockito.MockitoAnnotations.initMocks;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
@RunWith(MockitoJUnitRunner.class)
public class UMAPolicyTest {

    @Mock
    Request mockRequest;

    @Mock
    Response mockResponse;

    @Mock
    ExecutionContext mockExecutionContext;

    @Mock
    PolicyChain mockPolicychain;

    @Mock
    ResourceManager resourceManager;

    @Mock
    Uma2KeycloakResource customOAuth2Resource;

    @Mock
    Uma2KeycloakResourceConfiguration oauth2ResourceConfiguration;

    @Mock
    UMAPolicyConfiguration umaPolicyConfiguration;
    
    //To be mocked
    AuthzClient client;

    private static final String DEFAULT_OAUTH_SCOPE_SEPARATOR = " ";
    
	private static final String keyCloakconfig = "{\n" + 
				"  \"realm\": \"master\",\n" + 
				"  \"auth-server-url\": \"http://127.0.0.1:8081/auth\",\n" + 
				"  \"ssl-required\": \"external\",\n" + 
				"  \"resource\": \"test\",\n" + 
				"  \"credentials\": {\n" + 
				"    \"secret\": \"2ac7b9f0-24b2-4e72-a4d2-733bc344a15a\"\n" + 
				"  },\n" + 
				"  \"confidential-port\": 0,\n" + 
				"  \"policy-enforcer\": {}\n" + 
				"}";

    @Before
    public void init() {
        initMocks(this);
    		try {
				client = AuthzClient.create(JsonSerialization.readValue(keyCloakconfig, Configuration.class));
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
    		System.setProperty("http.proxyHost","127.0.0.1");
    	    System.setProperty("http.proxyPort","8080");
    }

    @Test
    public void shouldFailedIfNoOAuthResourceProvided() throws IOException {
        UMAPolicy policy = new UMAPolicy(umaPolicyConfiguration);

        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldReplaceId() throws IOException{
    		String pattern =  "\\/v2\\/entities\\/(.*)$";
	    	Generex generex = new Generex(pattern);
	    	String baseUri = generex.random();
	    String result = replaceGroup(pattern,baseUri,1,"123");
	    System.out.println(result);
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
    
    
    @Test
    public void shouldFailedIfNoAuthorizationHeaderProvided() throws IOException {
        
        UMAPolicy policy = new UMAPolicy(umaPolicyConfiguration);

        when(mockRequest.headers()).thenReturn(new HttpHeaders());
        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(resourceManager.getResource(umaPolicyConfiguration.getOauthResource(), Uma2KeycloakResource.class)).thenReturn(customOAuth2Resource);
        when(mockResponse.headers()).thenReturn(new HttpHeaders());

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldFailedIfNoAuthorizationHeaderBearerProvided() throws IOException {
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put("Authorization", "Basic Test");
            }
        });
        UMAPolicy policy = new UMAPolicy(umaPolicyConfiguration);

        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(resourceManager.getResource(umaPolicyConfiguration.getOauthResource(), Uma2KeycloakResource.class)).thenReturn(customOAuth2Resource);
        when(mockRequest.headers()).thenReturn(headers);
        when(mockResponse.headers()).thenReturn(new HttpHeaders());

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldFailedIfNoAuthorizationAccessTokenBearerIsEmptyProvided() throws IOException {
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put("Authorization", "Bearer");
            }
        });
        UMAPolicy policy = new UMAPolicy(umaPolicyConfiguration);

        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(resourceManager.getResource(umaPolicyConfiguration.getOauthResource(), Uma2KeycloakResource.class)).thenReturn(customOAuth2Resource);
        when(mockRequest.headers()).thenReturn(headers);
        when(mockResponse.headers()).thenReturn(new HttpHeaders());

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldCallOAuthResource() throws Exception {
        final HttpHeaders headers = new HttpHeaders();
		AccessTokenResponse atr = client.obtainAccessToken("admin", "admin");	 //why the source token is not valid???
        
        String bearer = atr.getToken();
        
        headers.setAll(new HashMap<String, String>() {
            {
                put("Authorization", "Bearer " + bearer);
            }
        });
        UMAPolicy policy = new UMAPolicy(umaPolicyConfiguration);
        when(mockRequest.headers()).thenReturn(headers);
        when(mockResponse.headers()).thenReturn(new HttpHeaders());
        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(umaPolicyConfiguration.getOauthResource()).thenReturn("oauth2");
        when(resourceManager.getResource(umaPolicyConfiguration.getOauthResource(), Uma2KeycloakResource.class)).thenReturn(customOAuth2Resource);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(customOAuth2Resource).introspect(eq(bearer), any(Handler.class));
        verify(mockExecutionContext).setAttribute(eq(UMAPolicy.CONTEXT_ATTRIBUTE_OAUTH_ACCESS_TOKEN), eq(bearer));
    }

    @Test
    public void shouldCallUmaAndAuthorize() throws Exception {
        final HttpHeaders headers = new HttpHeaders();
        AccessTokenResponse atr = client.obtainAccessToken("admin", "admin");	 //why the source token is not valid???
        
        String bearer = atr.getToken();
        
        headers.setAll(new HashMap<String, String>() {
            {
                put("Authorization", "Bearer " + bearer);
            }
        });

        UMAPolicy policy = new UMAPolicy(umaPolicyConfiguration);
        when(mockRequest.headers()).thenReturn(headers);
        when(mockResponse.headers()).thenReturn(new HttpHeaders());
        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(umaPolicyConfiguration.getOauthResource()).thenReturn("oauth2");
        when(resourceManager.getResource(umaPolicyConfiguration.getOauthResource(), Uma2KeycloakResource.class)).thenReturn(customOAuth2Resource);
        when(umaPolicyConfiguration.getExtractResourceID(HttpMethod.GET)).thenReturn(UMAPolicy.RESOURCEID_PATH);
        when(umaPolicyConfiguration.getResourceIDPattern(UMAPolicy.RESOURCEID_PATH)).thenReturn("/v2/entities/(.*)?");
        when(mockRequest.pathInfo()).thenReturn("/v2/entities/6990");
        when(mockRequest.method()).thenReturn(HttpMethod.GET);
        when(mockExecutionContext.getAttribute(UMAPolicy.CONTEXT_ATTRIBUTE_RESOURCE_ID)).thenReturn("6990");
        when(umaPolicyConfiguration.getResourceScopeMethod(HttpMethod.GET)).thenReturn(new String[] {"read"});
        when(oauth2ResourceConfiguration.getKeycloakConfiguration()).thenReturn(keyCloakconfig);
        when(customOAuth2Resource.configuration()).thenReturn(oauth2ResourceConfiguration);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockExecutionContext).setAttribute(eq(UMAPolicy.CONTEXT_ATTRIBUTE_OAUTH_ACCESS_TOKEN), eq(bearer));
        verify(mockExecutionContext).setAttribute(eq(UMAPolicy.CONTEXT_ATTRIBUTE_RESOURCE_ID), eq("6990"));
        verify(mockPolicychain).doNext(mockRequest, mockResponse);
    }
    
    @Test
    public void shouldCallUmaAndListResources() throws Exception {
        final HttpHeaders headers = new HttpHeaders();
        AccessTokenResponse atr = client.obtainAccessToken("admin", "admin");	 //why the source token is not valid???
        
        String bearer = atr.getToken();
        
        headers.setAll(new HashMap<String, String>() {
            {
                put("Authorization", "Bearer " + bearer);
            }
        });
        
        LinkedMultiValueMap<String, String> parameters = new LinkedMultiValueMap<String, String>();
        
        parameters.set("id", "6990");

        UMAPolicy policy = new UMAPolicy(umaPolicyConfiguration);
        when(mockRequest.headers()).thenReturn(headers);
        when(mockResponse.headers()).thenReturn(new HttpHeaders());
        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(umaPolicyConfiguration.getOauthResource()).thenReturn("oauth2");
        when(resourceManager.getResource(umaPolicyConfiguration.getOauthResource(), Uma2KeycloakResource.class)).thenReturn(customOAuth2Resource);
        when(umaPolicyConfiguration.getExtractResourceID(HttpMethod.GET)).thenReturn(UMAPolicy.RESOURCEID_PATH);
        when(umaPolicyConfiguration.getResourceIDPattern(UMAPolicy.RESOURCEID_PATH)).thenReturn("/v2/entities/(.*)?");
        when(mockRequest.pathInfo()).thenReturn("/v2/entities");
        when(mockRequest.method()).thenReturn(HttpMethod.GET);
        when(mockExecutionContext.getAttribute(UMAPolicy.CONTEXT_ATTRIBUTE_RESOURCE_ID)).thenReturn(null);
        when(umaPolicyConfiguration.getResourceScopeMethod(HttpMethod.GET)).thenReturn(new String[] {"read"});
        
        when(mockRequest.parameters()).thenReturn(parameters);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockExecutionContext).setAttribute(eq(UMAPolicy.CONTEXT_ATTRIBUTE_OAUTH_ACCESS_TOKEN), eq(bearer));
        verify(mockPolicychain).doNext(mockRequest, mockResponse);
    }
    
    @Test
    public void jsonPathTest() {
    		String test = "[\n" + 
    				"    {\n" + 
    				"        \"id\": \"299500\",\n" + 
    				"        \"type\": \"AirQualityObserved\",\n" + 
    				"        \"aqi\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"21\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"city\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"Charleroi\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"h\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 0,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"location\": {\n" + 
    				"            \"type\": \"geo:point\",\n" + 
    				"            \"value\": \"50.4093114542045, 4.45217178148666\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"measurand\": {\n" + 
    				"            \"type\": \"StructuredValue\",\n" + 
    				"            \"value\": [\n" + 
    				"                \"pm10, 21, ugm3, PM10\",\n" + 
    				"                \"h, 0, %, Relative Humidity\",\n" + 
    				"                \"p, 0, hPa, Pressure\",\n" + 
    				"                \"no2, 16, ugm3, Nitrogen Dioxide\",\n" + 
    				"                \"pm25, 21, ugm3, PM25\",\n" + 
    				"                \"t, 0, °C, Ambient Temperature\"\n" + 
    				"            ],\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"no2\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"16\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"p\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 0,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"pm10\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"21\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"pm25\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"21\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"t\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 0,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"url\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"https://orion.s.orchestracities.com/v2/entities/Charleroi\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        }\n" + 
    				"    },\n" + 
    				"    {\n" + 
    				"        \"id\": \"172\",\n" + 
    				"        \"type\": \"Open311ServiceType\",\n" + 
    				"        \"about\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"Sanitation\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"description\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"Give feedback if you find that property or equipment is broken.\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"keywords\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"bench,parks,trashbins\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"last_search\": {\n" + 
    				"            \"type\": \"datetime\",\n" + 
    				"            \"value\": \"2018-05-28 11:20:38\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"metadata\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"false\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"service_name\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"Vandalism\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        }\n" + 
    				"    },\n" + 
    				"    {\n" + 
    				"        \"id\": \"246\",\n" + 
    				"        \"type\": \"Open311ServiceType\",\n" + 
    				"        \"about\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"Sanitation\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"description\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"Report if you find garbage or overflowing trash bins.\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"keywords\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"garbage,debris\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"last_search\": {\n" + 
    				"            \"type\": \"datetime\",\n" + 
    				"            \"value\": \"2018-05-28 11:20:43\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"metadata\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"false\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"service_name\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"Sanitation violation\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        }\n" + 
    				"    },\n" + 
    				"    {\n" + 
    				"        \"id\": \"Antwerpen-linkeroever\",\n" + 
    				"        \"type\": \"CityInfo\",\n" + 
    				"        \"countryCode\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"GB\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"elevation\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 13,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"feature\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"city\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"lang\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"en\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"last_update\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"2018-05-28 11:20:20\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"lat\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 51.220556,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"lng\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 4.399722,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"rank\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 92,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"summary\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"Antwerp District coincides with the old city of Antwerp. Since the municipality and contemporary city of Antwerp in the Flemish Region of Belgium was decentralized in 2000 this district level of government steadily increased its administrative powers ...\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"title\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"Antwerp district\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"wikipediaUrl\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"en.wikipedia.orgwikiAntwerp28district29\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        }\n" + 
    				"    },\n" + 
    				"    {\n" + 
    				"        \"id\": \"8006\",\n" + 
    				"        \"type\": \"AirQualityObserved\",\n" + 
    				"        \"aqi\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 46,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"city\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"Antwerpen-linkeroever\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"h\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 52.8,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"location\": {\n" + 
    				"            \"type\": \"geo:point\",\n" + 
    				"            \"value\": \"51.2361942021, 4.38522368489\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"measurand\": {\n" + 
    				"            \"type\": \"StructuredValue\",\n" + 
    				"            \"value\": [\n" + 
    				"                \"pm10, 25, ugm3, PM10\",\n" + 
    				"                \"p, 1019.3, hPa, Pressure\",\n" + 
    				"                \"no2, 11.5, ugm3, Nitrogen Dioxide\",\n" + 
    				"                \"w, 4.4, NA, w\",\n" + 
    				"                \"pm25, 46, ugm3, PM25\"\n" + 
    				"            ],\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"no2\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 11.5,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"p\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 1019.3,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"pm10\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 25,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"pm25\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 46,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"t\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 26.8,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"url\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"https://orion.s.orchestracities.com/v2/entities/Antwerpen-linkeroever\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        }\n" + 
    				"    },\n" + 
    				"    {\n" + 
    				"        \"id\": \"Antwerpen\",\n" + 
    				"        \"type\": \"CityInfo\",\n" + 
    				"        \"countryCode\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"BE\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"elevation\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 13,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"feature\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"city\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"geoNameId\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 2803140,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"lang\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"en\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"last_update\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"2018-05-28 11:20:23\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"lat\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 51.220555556,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"lng\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 4.399722222,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"rank\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 100,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"summary\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"Antwerp is a city in Belgium which is the capital of Antwerp province. With a population of 510610 Population of all municipalities in Belgium as of 1 January 2014. Retrieved on 20 July 2014. it is the most populous city in Flanders. Its metropolitan area houses around 1200000 people ...\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"thumbnailImg\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"httpwww.geonames.orgimgwikipedia128000thumb127737100.jpg\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"title\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"Antwerp\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"wikipediaUrl\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"en.wikipedia.orgwikiAntwerp\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        }\n" + 
    				"    },\n" + 
    				"    {\n" + 
    				"        \"id\": \"6987\",\n" + 
    				"        \"type\": \"AirQualityObserved\",\n" + 
    				"        \"aqi\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 50,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"city\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"Antwerpen\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"h\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 60.6,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"location\": {\n" + 
    				"            \"type\": \"geo:point\",\n" + 
    				"            \"value\": \"4.42439900738, 51.2609897097\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"measurand\": {\n" + 
    				"            \"type\": \"StructuredValue\",\n" + 
    				"            \"value\": [\n" + 
    				"                \"pm10, 29, ugm3, PM10\",\n" + 
    				"                \"p, 1018.3, hPa, Pressure\",\n" + 
    				"                \"w, 1.6, NA, w\",\n" + 
    				"                \"no2, 13.3, ugm3, Nitrogen Dioxide\",\n" + 
    				"                \"pm25, 50, ugm3, PM25\"\n" + 
    				"            ],\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"no2\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 13.3,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"p\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 1018.3,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"pm10\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 29,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"pm25\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 50,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"t\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 27.7,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"url\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"https://orion.s.orchestracities.com/v2/entities/Antwerpen\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        }\n" + 
    				"    },\n" + 
    				"    {\n" + 
    				"        \"id\": \"8905\",\n" + 
    				"        \"type\": \"AirQualityObserved\",\n" + 
    				"        \"aqi\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 42,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"city\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"Antwerpen\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"h\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 55.5,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"location\": {\n" + 
    				"            \"type\": \"geo:point\",\n" + 
    				"            \"value\": \"51.23089, 4.422911\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"measurand\": {\n" + 
    				"            \"type\": \"StructuredValue\",\n" + 
    				"            \"value\": [\n" + 
    				"                \"wg, 10.5, NA, wg\",\n" + 
    				"                \"pm10, 21, ugm3, PM10\",\n" + 
    				"                \"pm25, 42, ugm3, PM25\",\n" + 
    				"                \"no2, 13.3, ugm3, Nitrogen Dioxide\"\n" + 
    				"            ],\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"no2\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 13.3,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"p\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 1018.4,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"pm10\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 21,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"pm25\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 42,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"t\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 28.8,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"url\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"https://orion.s.orchestracities.com/v2/entities/Antwerpen\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        }\n" + 
    				"    },\n" + 
    				"    {\n" + 
    				"        \"id\": \"8906\",\n" + 
    				"        \"type\": \"AirQualityObserved\",\n" + 
    				"        \"aqi\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 50,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"city\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"Antwerpen\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"h\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 52.8,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"location\": {\n" + 
    				"            \"type\": \"geo:point\",\n" + 
    				"            \"value\": \"51.2056589, 4.4180728\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"measurand\": {\n" + 
    				"            \"type\": \"StructuredValue\",\n" + 
    				"            \"value\": [\n" + 
    				"                \"w, 4.4, NA, w\",\n" + 
    				"                \"pm25, 50, ugm3, PM25\",\n" + 
    				"                \"pm10, 36, ugm3, PM10\",\n" + 
    				"                \"p, 1019.3, hPa, Pressure\"\n" + 
    				"            ],\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"p\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 1019.3,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"pm10\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 36,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"pm25\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 50,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"t\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 26.8,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"url\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"https://orion.s.orchestracities.com/v2/entities/Antwerpen\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        }\n" + 
    				"    },\n" + 
    				"    {\n" + 
    				"        \"id\": \"176\",\n" + 
    				"        \"type\": \"Open311ServiceType\",\n" + 
    				"        \"about\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"Sanitation\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"description\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"Report if graffiti or other paintings need removal.\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"keywords\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"graffiti\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"last_search\": {\n" + 
    				"            \"type\": \"datetime\",\n" + 
    				"            \"value\": \"2018-05-28 11:20:23\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"metadata\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"false\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"service_name\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"Graffiti removal\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        }\n" + 
    				"    },\n" + 
    				"    {\n" + 
    				"        \"id\": \"8907\",\n" + 
    				"        \"type\": \"AirQualityObserved\",\n" + 
    				"        \"aqi\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 38,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"city\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"Antwerpen\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"h\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 57.3,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"location\": {\n" + 
    				"            \"type\": \"geo:point\",\n" + 
    				"            \"value\": \"51.1761465, 4.4133872\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"measurand\": {\n" + 
    				"            \"type\": \"StructuredValue\",\n" + 
    				"            \"value\": [\n" + 
    				"                \"pm10, 20, ugm3, PM10\",\n" + 
    				"                \"p, 1018.2, hPa, Pressure\",\n" + 
    				"                \"w, 3.6, NA, w\",\n" + 
    				"                \"pm25, 38, ugm3, PM25\",\n" + 
    				"                \"no2, 5.5, ugm3, Nitrogen Dioxide\"\n" + 
    				"            ],\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"no2\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 5.5,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"p\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 1018.2,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"pm10\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 20,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"pm25\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 38,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"t\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 26.4,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"url\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"https://orion.s.orchestracities.com/v2/entities/Antwerpen\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        }\n" + 
    				"    },\n" + 
    				"    {\n" + 
    				"        \"id\": \"Kallo\",\n" + 
    				"        \"type\": \"CityInfo\",\n" + 
    				"        \"countryCode\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"BE\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"elevation\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 14,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"feature\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"city\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"geoNameId\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 2802030,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"lang\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"en\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"last_update\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"2018-05-28 11:20:24\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"lat\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 51.213333333,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"lng\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 4.258055556,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"rank\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 97,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"summary\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"Beveren is a municipality located in the Belgian province of East Flanders. The municipality comprises the towns of Beveren proper Doel Haasdonk Kallo Kieldrecht Melsele Verrebroek and Vrasene. The port of the Waasland Dutch Waaslandhaven is located in Beveren on the left bank of the ...\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"thumbnailImg\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"httpwww.geonames.orgimgwikipedia143000thumb142410100.jpg\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"title\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"Beveren\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"wikipediaUrl\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"en.wikipedia.orgwikiBeveren\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        }\n" + 
    				"    },\n" + 
    				"    {\n" + 
    				"        \"id\": \"3014\",\n" + 
    				"        \"type\": \"AirQualityObserved\",\n" + 
    				"        \"aqi\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 55,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"city\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"Kallo\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"h\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 55.3,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"location\": {\n" + 
    				"            \"type\": \"geo:point\",\n" + 
    				"            \"value\": \"51.290667529, 4.29332947737\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"measurand\": {\n" + 
    				"            \"type\": \"StructuredValue\",\n" + 
    				"            \"value\": [\n" + 
    				"                \"pm10, 43, ugm3, PM10\",\n" + 
    				"                \"p, 1017.6, hPa, Pressure\",\n" + 
    				"                \"w, 2.6, NA, w\",\n" + 
    				"                \"pm25, 55, ugm3, PM25\"\n" + 
    				"            ],\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"p\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 1017.6,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"pm10\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 43,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"pm25\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 55,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"t\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 28.1,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"url\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"https://orion.s.orchestracities.com/v2/entities/Kallo\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        }\n" + 
    				"    },\n" + 
    				"    {\n" + 
    				"        \"id\": \"Gent\",\n" + 
    				"        \"type\": \"CityInfo\",\n" + 
    				"        \"countryCode\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"NL\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"elevation\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 4,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"feature\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"city\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"geoNameId\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 2747750,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"lang\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"en\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"last_update\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"2018-05-28 11:20:28\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"lat\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 51.227778,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"lng\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 3.797222,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"rank\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 96,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"summary\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"Sas van Gent is a town in the Netherlands. It is located in the Dutch province of Zeeland. It is a part of the municipality of Terneuzen and lies about 30 km south of Vlissingen on the border with Belgium. The GhentTerneuzen Canal passes through Sas van Gent and at that point there was a lock in ...\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"title\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"Sas van Gent\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"wikipediaUrl\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"en.wikipedia.orgwikiSasvanGent\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        }\n" + 
    				"    },\n" + 
    				"    {\n" + 
    				"        \"id\": \"8904\",\n" + 
    				"        \"type\": \"AirQualityObserved\",\n" + 
    				"        \"aqi\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 42,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"city\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"Gent\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"co\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 0.1,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"h\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 57.5,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"location\": {\n" + 
    				"            \"type\": \"geo:point\",\n" + 
    				"            \"value\": \"51.0583317185, 3.72929817206\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"measurand\": {\n" + 
    				"            \"type\": \"StructuredValue\",\n" + 
    				"            \"value\": [\n" + 
    				"                \"co, 0.1, NA, co\",\n" + 
    				"                \"pm10, 20, ugm3, PM10\",\n" + 
    				"                \"p, 1021.9, hPa, Pressure\",\n" + 
    				"                \"so2, 0.6, NA, so2\",\n" + 
    				"                \"pm25, 42, ugm3, PM25\",\n" + 
    				"                \"o3, 35.8, NA, o3\",\n" + 
    				"                \"no2, 6.9, ugm3, Nitrogen Dioxide\"\n" + 
    				"            ],\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"no2\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 6.9,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"p\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 1021.9,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"pm10\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 20,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"pm25\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 42,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"t\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 26.6,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"url\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"https://orion.s.orchestracities.com/v2/entities/Gent\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        }\n" + 
    				"    },\n" + 
    				"    {\n" + 
    				"        \"id\": \"3022\",\n" + 
    				"        \"type\": \"AirQualityObserved\",\n" + 
    				"        \"aqi\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 42,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"city\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"Gent\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"h\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 57.5,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"location\": {\n" + 
    				"            \"type\": \"geo:point\",\n" + 
    				"            \"value\": \"51.0406894217, 3.73497148006\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"measurand\": {\n" + 
    				"            \"type\": \"StructuredValue\",\n" + 
    				"            \"value\": [\n" + 
    				"                \"pm10, 21, ugm3, PM10\",\n" + 
    				"                \"p, 1021.9, hPa, Pressure\",\n" + 
    				"                \"no2, 12.4, ugm3, Nitrogen Dioxide\",\n" + 
    				"                \"pm25, 42, ugm3, PM25\"\n" + 
    				"            ],\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"no2\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 12.4,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"p\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 1021.9,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"pm10\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 21,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"pm25\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 42,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"t\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 26.6,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"url\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"https://orion.s.orchestracities.com/v2/entities/Gent\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        }\n" + 
    				"    },\n" + 
    				"    {\n" + 
    				"        \"id\": \"Nogent-sur-marne\",\n" + 
    				"        \"type\": \"CityInfo\",\n" + 
    				"        \"countryCode\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"DE\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"elevation\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 81,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"feature\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"city\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"geoNameId\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 2990260,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"lang\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"en\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"last_update\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"2018-05-28 11:20:29\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"lat\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 48.8367,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"lng\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 2.4825,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"rank\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 100,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"summary\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"NogentsurMarne is a commune in the eastern suburbs of Paris France. It is located from the centre of Paris. NogentsurMarne is a sousprfecture of the ValdeMarne dpartement being the seat of the Arrondissement of NogentsurMarne.  ...\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"title\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"NogentsurMarne\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"wikipediaUrl\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"en.wikipedia.orgwikiNogentsurMarne\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        }\n" + 
    				"    },\n" + 
    				"    {\n" + 
    				"        \"id\": \"3102\",\n" + 
    				"        \"type\": \"AirQualityObserved\",\n" + 
    				"        \"aqi\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 67,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"city\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"Nogent-sur-marne\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"co\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 3.7,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"h\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 44.3,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"location\": {\n" + 
    				"            \"type\": \"geo:point\",\n" + 
    				"            \"value\": \"48.8408, 2.4844\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"measurand\": {\n" + 
    				"            \"type\": \"StructuredValue\",\n" + 
    				"            \"value\": [\n" + 
    				"                \"co, 3.7, NA, co\",\n" + 
    				"                \"pm10, 15, ugm3, PM10\",\n" + 
    				"                \"p, 1016.9, hPa, Pressure\",\n" + 
    				"                \"so2, 0.6, NA, so2\",\n" + 
    				"                \"no2, 9.6, ugm3, Nitrogen Dioxide\",\n" + 
    				"                \"w, 3.7, NA, w\",\n" + 
    				"                \"o3, 10, NA, o3\",\n" + 
    				"                \"pm25, 67, ugm3, PM25\"\n" + 
    				"            ],\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"no2\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 9.6,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"p\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 1016.9,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"pm10\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 15,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"pm25\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 67,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"t\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 22.2,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"url\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"https://orion.s.orchestracities.com/v2/entities/Nogent-sur-marne\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        }\n" + 
    				"    },\n" + 
    				"    {\n" + 
    				"        \"id\": \"Argentina\",\n" + 
    				"        \"type\": \"CityInfo\",\n" + 
    				"        \"countryCode\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"AR\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"elevation\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 32,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"feature\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"country\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"lang\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"en\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"last_update\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"2018-05-28 11:20:30\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"lat\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": -34.599722,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"lng\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": -58.381944,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"rank\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 100,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"summary\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"Argentina  officially the Argentine Republic  is a federal republic located in southeastern South America. Sharing the bulk of the Southern Cone with its neighbour Chile it is bordered by Bolivia and Paraguay to the north Brazil to the northeast Uruguay and the South Atlantic Ocean to the east ...\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"thumbnailImg\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"httpwww.geonames.orgimgwikipedia1000thumb122100.jpg\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"title\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"Argentina\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"wikipediaUrl\": {\n" + 
    				"            \"type\": \"Text\",\n" + 
    				"            \"value\": \"en.wikipedia.orgwikiArgentina\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        }\n" + 
    				"    },\n" + 
    				"    {\n" + 
    				"        \"id\": \"6700\",\n" + 
    				"        \"type\": \"AirQualityObserved\",\n" + 
    				"        \"aqi\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 59,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"city\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"Argentina\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"co\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 0.1,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"h\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 82.5,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"location\": {\n" + 
    				"            \"type\": \"geo:point\",\n" + 
    				"            \"value\": \"43.5389232, -5.6997771\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"measurand\": {\n" + 
    				"            \"type\": \"StructuredValue\",\n" + 
    				"            \"value\": [\n" + 
    				"                \"co, 0.1, NA, co\",\n" + 
    				"                \"pm10, 41, ugm3, PM10\",\n" + 
    				"                \"so2, 1.1, NA, so2\",\n" + 
    				"                \"pm25, 59, ugm3, PM25\",\n" + 
    				"                \"w, 0.3, NA, w\",\n" + 
    				"                \"o3, 17.5, NA, o3\",\n" + 
    				"                \"no2, 22.4, ugm3, Nitrogen Dioxide\"\n" + 
    				"            ],\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"no2\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 22.4,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"p\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 1017.4,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"pm10\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 41,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"pm25\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 59,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"t\": {\n" + 
    				"            \"type\": \"Number\",\n" + 
    				"            \"value\": 15.5,\n" + 
    				"            \"metadata\": {}\n" + 
    				"        },\n" + 
    				"        \"url\": {\n" + 
    				"            \"type\": \"string\",\n" + 
    				"            \"value\": \"https://orion.s.orchestracities.com/v2/entities/Argentina\",\n" + 
    				"            \"metadata\": {}\n" + 
    				"        }\n" + 
    				"    }\n" + 
    				"]";
    		JSONArray result = JsonPath.read(test, "$..[?(@.id==299500 || @.id==172)]");
    		result.size();
    }
    
    
    @Test
    public void jsonProtocolTest() {
    		String test = "{\"count\":3,\"protocols\":[{\"_id\":\"5a9eb104da30de7e7922e573\",\"description\":\"HTTP Ultralight 2.0 IoT Agent (Node.js version)\",\"protocol\":\"HTTP_UL\",\"resource\":\"/iot/ul\",\"iotagent\":\"http://ul-iot-agent:4041/config/iot\",\"__v\":0},{\"_id\":\"5a9f45cf45f63fe647800880\",\"description\":\"HTTP JSON IoT Agent (Node.js version)\",\"protocol\":\"HTTP_JSON\",\"resource\":\"/iot/json\",\"iotagent\":\"http://json-iot-agent:4041/config/iot\",\"__v\":0},{\"_id\":\"5aa28f51bf77b0d245058c35\",\"description\":\"OMA LWM2M IoT Agent COAP protocol (Node.js version)\",\"protocol\":\"COAP\",\"resource\":\"/iot/d\",\"iotagent\":\"https://iot-agent-lwm2m.s.orchestracities.com/config/config/iot\",\"__v\":0}]}";
    		JSONArray result = JsonPath.read(test, "    $.protocols[?(@._id==\"5a9eb104da30de7e7922e573\")]");
    		result.size();
    }
    

    
    @Test
    public void shouldCallUmaAndDeny() throws Exception {
        final HttpHeaders headers = new HttpHeaders();
        AccessTokenResponse atr = client.obtainAccessToken("admin", "admin");	 //why the source token is not valid???
        
        String bearer = atr.getToken();
        
        headers.setAll(new HashMap<String, String>() {
            {
                put("Authorization", "Bearer " + bearer);
            }
        });

        UMAPolicy policy = new UMAPolicy(umaPolicyConfiguration);
        when(mockRequest.headers()).thenReturn(headers);
        when(mockResponse.headers()).thenReturn(new HttpHeaders());
        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(umaPolicyConfiguration.getOauthResource()).thenReturn("oauth2");
        when(resourceManager.getResource(umaPolicyConfiguration.getOauthResource(), Uma2KeycloakResource.class)).thenReturn(customOAuth2Resource);
        when(umaPolicyConfiguration.getExtractResourceID(HttpMethod.GET)).thenReturn(UMAPolicy.RESOURCEID_PATH);
        when(umaPolicyConfiguration.getResourceIDPattern(UMAPolicy.RESOURCEID_PATH)).thenReturn("/v2/entities/(.*)?");
        when(mockRequest.pathInfo()).thenReturn("/v2/entities/8905");
        when(mockRequest.method()).thenReturn(HttpMethod.GET);
        when(mockExecutionContext.getAttribute(UMAPolicy.CONTEXT_ATTRIBUTE_RESOURCE_ID)).thenReturn("8905");
        when(umaPolicyConfiguration.getResourceScopeMethod(HttpMethod.GET)).thenReturn(new String[] {"read"});
        when(customOAuth2Resource.configuration().getKeycloakConfiguration()).thenReturn(keyCloakconfig);
        
        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockExecutionContext).setAttribute(eq(UMAPolicy.CONTEXT_ATTRIBUTE_OAUTH_ACCESS_TOKEN), eq(bearer));
        verify(mockExecutionContext).setAttribute(eq(UMAPolicy.CONTEXT_ATTRIBUTE_RESOURCE_ID), eq("8905"));
        verify(mockPolicychain).failWith(any(PolicyResult.class));;
    }

    @Test
    public void shouldValidScopes_noRequiredScopes() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/uma/oauth2-response01.json");
        boolean valid = UMAPolicy.hasRequiredScopes(jsonNode, null, DEFAULT_OAUTH_SCOPE_SEPARATOR);
        Assert.assertTrue(valid);
    }

    @Test
    public void shouldNotValidScopes_emptyOAuthResponse() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/uma/oauth2-response01.json");
        boolean valid = UMAPolicy.hasRequiredScopes(jsonNode, Collections.singletonList("read"), DEFAULT_OAUTH_SCOPE_SEPARATOR);
        Assert.assertFalse(valid);
    }

    @Test
    public void shouldValidScopes_emptyOAuthResponse() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/uma/oauth2-response02.json");
        boolean valid = UMAPolicy.hasRequiredScopes(jsonNode, Collections.singletonList("read"), DEFAULT_OAUTH_SCOPE_SEPARATOR);
        Assert.assertTrue(valid);
    }

    @Test
    public void shouldValidScopes_stringOfScopes() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/uma/oauth2-response04.json");
        boolean valid = UMAPolicy.hasRequiredScopes(jsonNode, Collections.singletonList("read"), DEFAULT_OAUTH_SCOPE_SEPARATOR);
        Assert.assertTrue(valid);
    }

    @Test
    public void shouldValidScopes_stringOfScopes_customSeparator() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/uma/oauth2-response06.json");
        boolean valid = UMAPolicy.hasRequiredScopes(jsonNode, Collections.singletonList("read"), ",");
        Assert.assertTrue(valid);
    }

    @Test
    public void shouldValidScopes_arrayOfScopes() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/uma/oauth2-response05.json");
        boolean valid = UMAPolicy.hasRequiredScopes(jsonNode, Collections.singletonList("read"), DEFAULT_OAUTH_SCOPE_SEPARATOR);
        Assert.assertTrue(valid);
    }

//    @Test
//    public void shouldFail_badIntrospection() throws IOException {
//        HttpHeaders httpHeaders = mock(HttpHeaders.class);
//        when(mockResponse.headers()).thenReturn(httpHeaders);
//        when(umaPolicyConfiguration.getKeycloakConfig()).thenReturn(keyCloakconfig);
//
//        UMAPolicy policy = new UMAPolicy(umaPolicyConfiguration);
//        Handler<OAuth2Response> handler = policy.handleResponse(mockPolicychain, mockRequest, mockResponse, mockExecutionContext);
//
//        String payload = readResource("/io/gravitee/policy/uma/oauth2-response03.json");
//        handler.handle(new OAuth2Response(false, payload));
//
//        verify(mockExecutionContext, never()).setAttribute(eq(UMAPolicy.CONTEXT_ATTRIBUTE_CLIENT_ID), anyString());
//        verify(httpHeaders).add(eq(HttpHeaders.WWW_AUTHENTICATE), anyString());
//        verify(mockPolicychain).failWith(any(PolicyResult.class));
//    }

//    @Test
//    public void shouldFail_exception() throws IOException {
//        HttpHeaders httpHeaders = mock(HttpHeaders.class);
//        when(mockResponse.headers()).thenReturn(httpHeaders);
//        when(umaPolicyConfiguration.getKeycloakConfig()).thenReturn(keyCloakconfig);
//
//        UMAPolicy policy = new UMAPolicy(umaPolicyConfiguration);
//        Handler<OAuth2Response> handler = policy.handleResponse(mockPolicychain, mockRequest, mockResponse, mockExecutionContext);
//
//        handler.handle(new OAuth2Response(new Exception()));
//
//        verify(mockExecutionContext, never()).setAttribute(eq(UMAPolicy.CONTEXT_ATTRIBUTE_CLIENT_ID), anyString());
//        verify(httpHeaders).add(eq(HttpHeaders.WWW_AUTHENTICATE), anyString());
//        verify(mockPolicychain).failWith(any(PolicyResult.class));
//    }

//    @Test
//    public void shouldFail_invalidResponseFormat() throws IOException {
//        HttpHeaders httpHeaders = mock(HttpHeaders.class);
//        when(mockResponse.headers()).thenReturn(httpHeaders);
//        when(umaPolicyConfiguration.getKeycloakConfig()).thenReturn(keyCloakconfig);
//
//        UMAPolicy policy = new UMAPolicy(umaPolicyConfiguration);
//        Handler<OAuth2Response> handler = policy.handleResponse(mockPolicychain, mockRequest, mockResponse, mockExecutionContext);
//
//        handler.handle(new OAuth2Response(true, "blablabla"));
//
//        verify(mockExecutionContext, never()).setAttribute(eq(UMAPolicy.CONTEXT_ATTRIBUTE_CLIENT_ID), anyString());
//        verify(httpHeaders).add(eq(HttpHeaders.WWW_AUTHENTICATE), anyString());
//        verify(mockPolicychain).failWith(any(PolicyResult.class));
//    }
//
//    @Test
//    public void shouldFail_goodIntrospection_noClientId() throws IOException {
//        HttpHeaders httpHeaders = mock(HttpHeaders.class);
//        when(mockResponse.headers()).thenReturn(httpHeaders);
//        when(umaPolicyConfiguration.getKeycloakConfig()).thenReturn(keyCloakconfig);
//
//        UMAPolicy policy = new UMAPolicy(umaPolicyConfiguration);
//        Handler<OAuth2Response> handler = policy.handleResponse(mockPolicychain, mockRequest, mockResponse, mockExecutionContext);
//
//        String payload = readResource("/io/gravitee/policy/uma/oauth2-response03.json");
//        handler.handle(new OAuth2Response(true, payload));
//
//        verify(mockExecutionContext, never()).setAttribute(eq(UMAPolicy.CONTEXT_ATTRIBUTE_CLIENT_ID), anyString());
//        verify(httpHeaders, never()).add(eq(HttpHeaders.WWW_AUTHENTICATE), anyString());
//        verify(mockPolicychain).doNext(mockRequest, mockResponse);
//    }

//    @Test
//    public void shouldValidate_goodIntrospection_withClientId() throws IOException {
//        HttpHeaders httpHeaders = mock(HttpHeaders.class);
//        when(mockResponse.headers()).thenReturn(httpHeaders);
//        when(umaPolicyConfiguration.isExtractPayload()).thenReturn(true);
//        when(umaPolicyConfiguration.getKeycloakConfig()).thenReturn(keyCloakconfig);
//
//        UMAPolicy policy = new UMAPolicy(umaPolicyConfiguration);
//        Handler<OAuth2Response> handler = policy.handleResponse(mockPolicychain, mockRequest, mockResponse, mockExecutionContext);
//
//        String payload = readResource("/io/gravitee/policy/uma/oauth2-response04.json");
//        handler.handle(new OAuth2Response(true, payload));
//
//        verify(mockExecutionContext).setAttribute(UMAPolicy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
//        verify(mockExecutionContext).setAttribute(UMAPolicy.CONTEXT_ATTRIBUTE_OAUTH_PAYLOAD, payload);
//        verify(mockPolicychain).doNext(mockRequest, mockResponse);
//    }

//    @Test
//    public void shouldValidate_goodIntrospection_withClientId_validScopes() throws IOException {
//        HttpHeaders httpHeaders = mock(HttpHeaders.class);
//        when(mockResponse.headers()).thenReturn(httpHeaders);
//        when(umaPolicyConfiguration.isCheckRequiredScopes()).thenReturn(true);
//        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
//        when(resourceManager.getResource(umaPolicyConfiguration.getOauthResource(), OAuth2Resource.class)).thenReturn(customOAuth2Resource);
//        when(customOAuth2Resource.getScopeSeparator()).thenReturn(DEFAULT_OAUTH_SCOPE_SEPARATOR);
//        when(umaPolicyConfiguration.getKeycloakConfig()).thenReturn(keyCloakconfig);
//
//        UMAPolicy policy = new UMAPolicy(umaPolicyConfiguration);
//     //   Handler<OAuth2Response> handler = policy.handleResponse(mockPolicychain, mockRequest, mockResponse, mockExecutionContext);
//
//        String payload = readResource("/io/gravitee/policy/uma/oauth2-response04.json");
//        handler.handle(new OAuth2Response(true, payload));
//
//        verify(mockExecutionContext).setAttribute(UMAPolicy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
//        verify(mockPolicychain).doNext(mockRequest, mockResponse);
//    }

//    @Test
//    public void shouldValidate_goodIntrospection_withClientId_invalidScopes() throws IOException {
//        HttpHeaders httpHeaders = mock(HttpHeaders.class);
//        when(mockResponse.headers()).thenReturn(httpHeaders);
//        when(umaPolicyConfiguration.isCheckRequiredScopes()).thenReturn(true);
//        when(umaPolicyConfiguration.getRequiredScopes()).thenReturn(Collections.singletonList("super-admin"));
//        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
//        when(resourceManager.getResource(umaPolicyConfiguration.getOauthResource(), OAuth2Resource.class)).thenReturn(customOAuth2Resource);
//        when(customOAuth2Resource.getScopeSeparator()).thenReturn(DEFAULT_OAUTH_SCOPE_SEPARATOR);
//        when(umaPolicyConfiguration.getKeycloakConfig()).thenReturn(keyCloakconfig);
//
//        UMAPolicy policy = new UMAPolicy(umaPolicyConfiguration);
//        Handler<OAuth2Response> handler = policy.handleResponse(mockPolicychain, mockRequest, mockResponse, mockExecutionContext);
//
//        String payload = readResource("/io/gravitee/policy/uma/oauth2-response04.json");
//        handler.handle(new OAuth2Response(true, payload));
//
//        verify(mockPolicychain).failWith(any(PolicyResult.class));
//    }
    
    @Test
    public void testResourceIdFromPath() throws IOException {
    		UMAPolicy policy = new UMAPolicy(umaPolicyConfiguration);
	    	String path = "/v2/entities/A";
	    	String regex = "/v2/entities/(.*)?";
	    	
	    	String resourceId = policy.getResourceIdFromPlainText(path, regex);
	    	Assert.assertTrue("A".equals(resourceId));
	    	
	    	path = "/v2/entities/A/attr/temperature";
	    regex = "/v2/entities/([^/]*)";
	    	
	    resourceId = policy.getResourceIdFromPlainText(path, regex);
	    	Assert.assertTrue("A".equals(resourceId));
	    	
	    	path = "/v2/entities/A/attr/temperature/value";
	    regex = "/v2/entities/([^/]*)";
	    	
	    resourceId = policy.getResourceIdFromPlainText(path, regex);
	    	Assert.assertTrue("A".equals(resourceId));
	    	
	    	path = "/v2/entities/A/attr/temperature/value";
	    regex = "/v2/entities/([^/]*)$";
	    	
	    resourceId = policy.getResourceIdFromPlainText(path, regex);
	    	Assert.assertTrue("A".equals(resourceId));
    }
    
    @Test
    public void testResourceIdFromPath2() throws IOException {
    		UMAPolicy policy = new UMAPolicy(umaPolicyConfiguration);
	    	String path = "/iot/services?apikey=12345678910";
	    	String regex = "\\/iot\\/services\\?apikey=(.*)";
	    	Pattern p = Pattern.compile(regex);
	    Matcher m = p.matcher(path);
	    if(m.find())
	    	  System.out.println("found");
    }
    
    @Test
    public void testResourceIdFromJson() throws IOException {
		UMAPolicy policy = new UMAPolicy(umaPolicyConfiguration);
	    	String json = "{\n" + 
	    			"    \"id\": \"Room1\",\n" + 
	    			"    \"pressure\": {\n" + 
	    			"        \"metadata\": {},\n" + 
	    			"        \"type\": \"Integer\",\n" + 
	    			"        \"value\": 720\n" + 
	    			"    },\n" + 
	    			"    \"temperature\": {\n" + 
	    			"        \"metadata\": {},\n" + 
	    			"        \"type\": \"Float\",\n" + 
	    			"        \"value\": 23\n" + 
	    			"    },\n" + 
	    			"    \"type\": \"Room\"\n" + 
	    			"}";
	    	String query = "$.id";
	    	
	    	String resourceId = policy.getResourceIdFromJson(json, query);
	    	Assert.assertTrue("Room1".equals(resourceId));
	    	
	    	json = "{\n" + 
	    			"    \"data\": [\n" + 
	    			"        {\n" + 
	    			"            \"id\": \"Room1\",\n" + 
	    			"            \"temperature\": {\n" + 
	    			"                \"metadata\": {},\n" + 
	    			"                \"type\": \"Float\",\n" + 
	    			"                \"value\": 28.5\n" + 
	    			"            },\n" + 
	    			"            \"type\": \"Room\"\n" + 
	    			"        }\n" + 
	    			"    ],\n" + 
	    			"    \"subscriptionId\": \"57458eb60962ef754e7c0998\"\n" + 
	    			"}";
	    	
	    	query = "$.subscriptionId";
	    	
	    	resourceId = policy.getResourceIdFromJson(json, query);
	    	Assert.assertTrue("57458eb60962ef754e7c0998".equals(resourceId));
    }
    
    @Test
    public void testResourceAttributesFromJson() throws IOException {
		UMAPolicy policy = new UMAPolicy(umaPolicyConfiguration);
	    	String json = "{\n" + 
	    			"    \"id\": \"Room1\",\n" + 
	    			"    \"pressure\": {\n" + 
	    			"        \"metadata\": {},\n" + 
	    			"        \"type\": \"Integer\",\n" + 
	    			"        \"value\": 720\n" + 
	    			"    },\n" + 
	    			"    \"temperature\": {\n" + 
	    			"        \"metadata\": {},\n" + 
	    			"        \"type\": \"Float\",\n" + 
	    			"        \"value\": 23\n" + 
	    			"    },\n" + 
	    			"    \"type\": \"Room\"\n" + 
	    			"}";
	    	String query = "^(?!(id|type)$)";
	    List<Entry<String, JsonNode>> attributes = policy.getAttributesFromJson(json, query);
		Assert.assertTrue(attributes.size() == 2);
    }
    
    
//    @Test
//    public void createResourceFromJsonBody() throws IOException {
//        HttpHeaders httpHeaders = mock(HttpHeaders.class);
//        when(mockResponse.headers()).thenReturn(httpHeaders);
//        when(umaPolicyConfiguration.isCheckRequiredScopes()).thenReturn(true);
//        when(umaPolicyConfiguration.getRequiredScopes()).thenReturn(Collections.singletonList("super-admin"));
//        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
//        when(resourceManager.getResource(umaPolicyConfiguration.getOauthResource(), OAuth2Resource.class)).thenReturn(customOAuth2Resource);
//        when(customOAuth2Resource.getScopeSeparator()).thenReturn(DEFAULT_OAUTH_SCOPE_SEPARATOR);
//
//        UMAPolicy policy = new UMAPolicy(umaPolicyConfiguration);
//        Handler<OAuth2Response> handler = policy.handleResponse(mockPolicychain, mockRequest, mockResponse, mockExecutionContext);
//
//        String payload = readResource("/io/gravitee/policy/uma/oauth2-response04.json");
//        handler.handle(new OAuth2Response(true, payload));
//
//        verify(mockPolicychain).failWith(any(PolicyResult.class));
//    }

    private JsonNode readJsonResource(String resource) throws IOException {
        return UMAPolicy.MAPPER.readTree(this.getClass().getResourceAsStream(resource));
    }

    private String readResource(String resource) throws IOException {
        InputStream stream = this.getClass().getResourceAsStream(resource);
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int length;
        while ((length = stream.read(buffer)) != -1) {
            result.write(buffer, 0, length);
        }
        return result.toString(StandardCharsets.UTF_8.name());
    }
}
