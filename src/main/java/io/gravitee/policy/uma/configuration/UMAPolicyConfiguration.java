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
package io.gravitee.policy.uma.configuration;

import io.gravitee.common.http.HttpMethod;
import io.gravitee.policy.api.PolicyConfiguration;
import io.gravitee.policy.uma.UMAPolicy;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Federico M. Facca (federico.facca at martel-innovate.com)
 */
public class UMAPolicyConfiguration implements PolicyConfiguration {

    private String oauthResource;
    
    private List<String> resourceScopesGET = new ArrayList<>();
    
    private List<String> resourceScopesPOST = new ArrayList<>();
    
    private List<String> resourceScopesPUT = new ArrayList<>();
    
    private List<String> resourceScopesDELETE = new ArrayList<>();
    
    private List<String> resourceScopes = new ArrayList<>();
    
    private String resourceType;
    
    private String resourceTypeAttr;
    
    private boolean includeSubPath;
    
    private boolean allFilterOnResponse;
    
    private boolean createOnResponse;
    
    private boolean deleteOnResponse;
    
    private String getExtractResourceID;
    
    private String postExtractResourceID;

    private String putExtractResourceID;
    
    private String deleteExtractResourceID;
    
    private String resourceIDPatternPath;

    private String appendResourceFilter;
    
    private String resourceIDPatternQuery;
    
    private String resourceIDPatternBody;
    
    private String includeJsonAttributes;
    
    private String includeJsonAttrBaseURI;
    
    public String getOauthResource() {
        return oauthResource;
    }
    
    private String rootFilterOnResponse;
    
    private String objectFilterOnResponse;
    

    public void setOauthResource(String oauthResource) {
        this.oauthResource = oauthResource;
    }
    
    public String getResourceType() {
		return this.resourceType;
    }

	public void setResourceType(String resourceType) {
		this.resourceType = resourceType;
	}

	public boolean getIncludeSubPath() {
		return includeSubPath;
	}

	public void setIncludeSubPath(boolean includeSubPath) {
		this.includeSubPath = includeSubPath;
	}

	public boolean getCreateOnResponse() {
		return createOnResponse;
	}

	public void setCreateOnResponse(boolean createOnResponse) {
		this.createOnResponse = createOnResponse;
	}

	public boolean getDeleteOnResponse() {
		return deleteOnResponse;
	}

	public void setDeleteOnResponse(boolean deleteOnResponse) {
		this.deleteOnResponse = deleteOnResponse;
	}

	public String getGetExtractResourceID() {
		return getExtractResourceID;
	}

	public void setGetExtractResourceID(String getExtractResourceID) {
		this.getExtractResourceID = getExtractResourceID;
	}
	
	public String getPostExtractResourceID() {
		return postExtractResourceID;
	}

	public void setPostExtractResourceID(String postExtractResourceID) {
		this.postExtractResourceID = postExtractResourceID;
	}
	
	public String getPutExtractResourceID() {
		return putExtractResourceID;
	}

	public void setPutExtractResourceID(String putExtractResourceID) {
		this.putExtractResourceID = putExtractResourceID;
	}
	
	public String getDeleteExtractResourceID() {
		return deleteExtractResourceID;
	}

	public void setDeleteExtractResourceID(String deleteExtractResourceID) {
		this.deleteExtractResourceID = deleteExtractResourceID;
	}
	
	public String getExtractResourceID(HttpMethod method) {
		switch (method) {
		case DELETE:
			return getDeleteExtractResourceID();
		case POST:
			return getPostExtractResourceID();
		case PUT:
			return getPutExtractResourceID();
		case GET:
			return getGetExtractResourceID();
		}
		return UMAPolicy.RESOURCEID_PATH;
	}

	public String getResourceIDPattern(String patternType) {
		switch (patternType) {
		case UMAPolicy.RESOURCEID_PATH:
			return getResourceIDPatternPath();
		case UMAPolicy.RESOURCEID_QUERY:
			return getResourceIDPatternQuery();
		case UMAPolicy.RESOURCEID_REQUEST_BODY:
		case UMAPolicy.RESOURCEID_RESPONSE_BODY:
			return getResourceIDPatternBody();
		}
		return getResourceIDPatternPath();
	}
	
	public String[] getResourceScopeMethod(HttpMethod method) {
		switch (method) {
		case GET:
			return getResourceScopesGET().toArray(new String[] {});
		case POST:
			return getResourceScopesPOST().toArray(new String[] {});
		case PUT:
			return getResourceScopesPUT().toArray(new String[] {});
		case DELETE:
			return getResourceScopesDELETE().toArray(new String[] {});
		}
		return new String[] {};
	}
	
	public String getResourceIDPatternPath() {
		return resourceIDPatternPath;
	}

	public void setResourceIDPatternPath(String resourceIDPatternPath) {
		this.resourceIDPatternPath = resourceIDPatternPath;
	}
	
	public String getResourceIDPatternQuery() {
		return resourceIDPatternQuery;
	}
	
	public String getResourceIDPatternBody() {
		return resourceIDPatternBody;
	}

	public void setResourceIDPatternBody(String resourceIDPatternBody) {
		this.resourceIDPatternBody = resourceIDPatternBody;
	}
	
	public void setResourceIDPatternQuery(String resourceIDPatternQuery) {
		this.resourceIDPatternQuery = resourceIDPatternQuery;
	}

	public String getAppendResourceFilter() {
		return appendResourceFilter;
	}

	public void setAppendResourceFilter(String appendResourceFilter) {
		this.appendResourceFilter = appendResourceFilter;
	}

	public List<String> getResourceScopesGET() {
		return resourceScopesGET;
	}

	public void setResourceScopesGET(List<String> resourceScopesGET) {
		this.resourceScopesGET = resourceScopesGET;
	}

	public List<String> getResourceScopesPOST() {
		return resourceScopesPOST;
	}

	public void setResourceScopesPOST(List<String> resourceScopesPOST) {
		this.resourceScopesPOST = resourceScopesPOST;
	}

	public List<String> getResourceScopesPUT() {
		return resourceScopesPUT;
	}

	public void setResourceScopesPUT(List<String> resourceScopesPUT) {
		this.resourceScopesPUT = resourceScopesPUT;
	}

	public List<String> getResourceScopesDELETE() {
		return resourceScopesDELETE;
	}

	public void setResourceScopesDELETE(List<String> resourceScopesDELETE) {
		this.resourceScopesDELETE = resourceScopesDELETE;
	}

	public String getIncludeJsonAttributes() {
		return includeJsonAttributes;
	}

	public void setIncludeJsonAttributes(String includeJsonAttributes) {
		this.includeJsonAttributes = includeJsonAttributes;
	}

	public String getIncludeJsonAttrBaseURI() {
		return includeJsonAttrBaseURI;
	}

	public void setIncludeJsonAttrBaseURI(String includeJsonAttrBaseURI) {
		this.includeJsonAttrBaseURI = includeJsonAttrBaseURI;
	}

	public List<String> getResourceScopes() {
		return resourceScopes;
	}

	public void setResourceScopes(List<String> resourceScopes) {
		this.resourceScopes = resourceScopes;
	}

	public boolean getAllFilterOnResponse() {
		return allFilterOnResponse;
	}

	public void setAllFilterOnResponse(boolean allFilterOnResponse) {
		this.allFilterOnResponse = allFilterOnResponse;
	}

	public String getResourceTypeAttr() {
		return resourceTypeAttr;
	}

	public void setResourceTypeAttr(String resourceTypeAttr) {
		this.resourceTypeAttr = resourceTypeAttr;
	}

	public String getRootFilterOnResponse() {
		return rootFilterOnResponse;
	}

	public void setRootFilterOnResponse(String rootFilterOnResponse) {
		this.rootFilterOnResponse = rootFilterOnResponse;
	}

	public String getObjectFilterOnResponse() {
		return objectFilterOnResponse;
	}

	public void setObjectFilterOnResponse(String objectFilterOnResponse) {
		this.objectFilterOnResponse = objectFilterOnResponse;
	}
}
