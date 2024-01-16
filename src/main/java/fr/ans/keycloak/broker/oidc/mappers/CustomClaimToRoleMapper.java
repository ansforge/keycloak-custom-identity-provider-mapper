/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.ans.keycloak.broker.oidc.mappers;

import org.keycloak.broker.oidc.KeycloakOIDCIdentityProviderFactory;
import org.keycloak.broker.oidc.OIDCIdentityProviderFactory;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.ConfigConstants;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.provider.ProviderConfigProperty;

import org.keycloak.broker.oidc.KeycloakOIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.mappers.AbstractClaimToRoleMapper;

import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;

import org.keycloak.representations.JsonWebToken;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.keycloak.utils.RegexUtils.valueMatchesRegex;
import static org.keycloak.utils.JsonUtils.splitClaimPath;

/**
 *  Fork of AdvancedClaimToRoleMapper class by Bill Burke (bill@burkecentral.com)
 * @author <a href="mailto:cedric.panissod@esante.gouv.fr">Cedric Panissod</a>
 * @version $Revision: 1 $
 */
public class CustomClaimToRoleMapper extends AbstractClaimToRoleMapper {

    public static final String CLAIM_PROPERTY_NAME = "claims";
    public static final String ARE_CLAIM_VALUES_REGEX_PROPERTY_NAME = "are.claim.values.regex";

    public static final String[] COMPATIBLE_PROVIDERS = {KeycloakOIDCIdentityProviderFactory.PROVIDER_ID, OIDCIdentityProviderFactory.PROVIDER_ID};
    private static final Set<IdentityProviderSyncMode> IDENTITY_PROVIDER_SYNC_MODES = new HashSet<>(Arrays.asList(IdentityProviderSyncMode.values()));

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty claimsProperty = new ProviderConfigProperty();
        claimsProperty.setName(CLAIM_PROPERTY_NAME);
        claimsProperty.setLabel("Claims");
        claimsProperty.setHelpText("Name and value of the claims to search for in token. You can reference nested claims using a '.', i.e. 'address.locality'. To use dot (.) literally, escape it with backslash (\\.)");
        claimsProperty.setType(ProviderConfigProperty.MAP_TYPE);
        configProperties.add(claimsProperty);
        ProviderConfigProperty isClaimValueRegexProperty = new ProviderConfigProperty();
        isClaimValueRegexProperty.setName(ARE_CLAIM_VALUES_REGEX_PROPERTY_NAME);
        isClaimValueRegexProperty.setLabel("Regex Claim Values");
        isClaimValueRegexProperty.setHelpText("If enabled claim values are interpreted as regular expressions.");
        isClaimValueRegexProperty.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        configProperties.add(isClaimValueRegexProperty);
        ProviderConfigProperty roleProperty = new ProviderConfigProperty();
        roleProperty.setName(ConfigConstants.ROLE);
        roleProperty.setLabel("Role");
        roleProperty.setHelpText("Role to grant to user if claim is present. Click 'Select Role' button to browse roles, or just type it in the textbox. To reference a client role the syntax is clientname.clientrole, i.e. myclient.myrole");
        roleProperty.setType(ProviderConfigProperty.ROLE_TYPE);
        configProperties.add(roleProperty);
    }

    public static final String PROVIDER_ID = "oidc-custom-role-idp-mapper";

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return IDENTITY_PROVIDER_SYNC_MODES.contains(syncMode);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getDisplayCategory() {
        return "Role Importer";
    }

    @Override
    public String getDisplayType() {
        return "Custom Claim to Role";
    }

    @Override
    public String getHelpText() {
        return "If all claims exists, grant the user the specified realm or client role.";
    }

    private static List<Object> getCustomClaimValueFromArray(List<String> split, int index, List<Object> jsonInput) {
        final int lenSplit = split.size();
        final int lenInput = jsonInput.size();
        String component = "";
        int i = 0;
        for (String path : split) {
          i++;
          if (i == (index+1)) {
              component = path;
              break;
          }
        }
        int j = 0;
        List<Object> jsonTemp = new ArrayList<Object>();
        while (j < lenInput) {
             Map<String, Object> jsonObject = (Map<String, Object>)(jsonInput.get(j));
             Object val = jsonObject.get(component);
             if (val instanceof ArrayList) {
                 List<Object> jsonArray = (List<Object>)val;
                 List<Object> value = getCustomClaimValueFromArray(split, i, jsonArray);
                 return value;
             }
             jsonTemp.add(jsonObject.get(component));
             j++;
        }
        if ((i+1) < lenSplit) {
            List<Object> value = getCustomClaimValueFromArray(split, i, jsonTemp);
            return value;
        }
        return jsonTemp;
    }

    private static Object getCustomClaimValueFromMap(List<String> split, Map<String, Object> jsonInput) {
        final int length = split.size();
        Map<String, Object> jsonObject = jsonInput;
        int i = 0;
        for (String component : split) {
            i++;
            Object val = jsonObject.get(component);
            if (val instanceof ArrayList) {
                List<Object> jsonArray = (List<Object>)val;
                List<Object> value = getCustomClaimValueFromArray(split, i, jsonArray);
                return value;
            } else if (!(val instanceof Map)) {
                return null;
            }
            jsonObject = (Map<String, Object>)val;
            if (i == length) {
              return val;
            }
        }
        return null;
    }

    private static Object getCustomClaimValue(BrokeredIdentityContext context, String claim) {

        List<String> split = splitClaimPath(claim);
        Map<String, Object> jsonObject = null;

        {  // search access token
            JsonWebToken token = (JsonWebToken) context.getContextData().get(KeycloakOIDCIdentityProvider.VALIDATED_ACCESS_TOKEN);
            if (token != null) {
                jsonObject = token.getOtherClaims();
                Object value = getCustomClaimValueFromMap(split, jsonObject);
                if (value != null) return value;
            }

        }

        {  // search ID Token
            Object rawIdToken = context.getContextData().get(OIDCIdentityProvider.VALIDATED_ID_TOKEN);
            JsonWebToken idToken = null;

            if (rawIdToken instanceof String) {
                try {
                    idToken = new JWSInput(rawIdToken.toString()).readJsonContent(JsonWebToken.class);
                } catch (JWSInputException e) {
                    return null;
                }
            } else if (rawIdToken instanceof JsonWebToken) {
                idToken = (JsonWebToken) rawIdToken;
            }

            if (idToken != null) {
                jsonObject = idToken.getOtherClaims();
                Object value = getCustomClaimValueFromMap(split, jsonObject);
                if (value != null)
                    return value;
            }
        }

        {
            // search the OIDC UserInfo claim set (if any)
            JsonNode profileJsonNode = (JsonNode) context.getContextData().get(OIDCIdentityProvider.USER_INFO);
            ObjectMapper objectMapper = new ObjectMapper();
            jsonObject = objectMapper.convertValue(profileJsonNode, Map.class);
            Object value = getCustomClaimValueFromMap(split, jsonObject);
            if (value != null) return value;
        }
        return null;
    }

    @Override
    protected boolean applies(IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        Map<String, List<String>> claims = mapperModel.getConfigMap(CLAIM_PROPERTY_NAME);
        boolean areClaimValuesRegex = Boolean.parseBoolean(mapperModel.getConfig().get(ARE_CLAIM_VALUES_REGEX_PROPERTY_NAME));

        for (Map.Entry<String, List<String>> claim : claims.entrySet()) {
            Object claimValue = getCustomClaimValue(context, claim.getKey());
            for (String value : claim.getValue()) {
                boolean claimValuesMismatch = !(areClaimValuesRegex ? valueMatchesRegex(value, claimValue) : valueEquals(value, claimValue));
                if (claimValuesMismatch) {
                    return false;
                }
            }
        }

        return true;
    }
}
