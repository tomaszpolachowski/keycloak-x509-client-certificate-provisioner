/*
 * Copyright 2026 Tomasz Polachowski
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
 *
 */

package io.github.tomaszpolachowski.keycloak.authentication.authenticators.x509;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.Arrays.asList;

import org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticatorFactory;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

import static org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator.MAPPING_SOURCE_CERT_SUBJECTALTNAME_EMAIL;
import static org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator.MAPPING_SOURCE_CERT_SUBJECTALTNAME_OTHERNAME;
import static org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator.MAPPING_SOURCE_CERT_SUBJECTDN;

/**
 * @author <a href="mailto:tomasz@polachowski.pl">Tomasz Polachowski</a>
 * @version $Revision: 1 $
 *
 */
public class X509ClientCertificateProvisionerFactory extends AbstractX509ClientCertificateAuthenticatorFactory {

    private static final String[] mappingSources = {
        MAPPING_SOURCE_CERT_SUBJECTALTNAME_EMAIL,
        MAPPING_SOURCE_CERT_SUBJECTALTNAME_OTHERNAME,
        MAPPING_SOURCE_CERT_SUBJECTDN
    };

    public static final String PROVIDER_ID = "auth-x509-client-cert-provisioner";
    public static final X509ClientCertificateProvisioner SINGLETON =
            new X509ClientCertificateProvisioner();

    protected static final List<ProviderConfigProperty> configProperties;
    static {
            List<String> mappingSourceTypes = new LinkedList<>();
            Collections.addAll(mappingSourceTypes, mappingSources);

            ProviderConfigProperty emailMappingMethodList = new ProviderConfigProperty();
            emailMappingMethodList.setType(ProviderConfigProperty.LIST_TYPE);
            emailMappingMethodList.setName(X509ClientCertificateProvisioner.MAPPING_SOURCE_EMAIL_SELECTION);
            emailMappingMethodList.setLabel("User E-Mail Source");
            emailMappingMethodList.setHelpText("Choose how to extract user's email address from the provided X.509 certificate");
            emailMappingMethodList.setDefaultValue(mappingSources[1]);
            emailMappingMethodList.setOptions(mappingSourceTypes);

            ProviderConfigProperty emailDnMapping = new ProviderConfigProperty();
            emailDnMapping.setType(ProviderConfigProperty.STRING_TYPE);
            emailDnMapping.setName(X509ClientCertificateProvisioner.MAPPING_SOURCE_EMAIL_SELECTION_DN);
            emailDnMapping.setLabel("DN attribute for user's email address");
            emailDnMapping.setHelpText(String.format("An attribute of certificate's Distinguish Name (DN) from which to get user's email address. Required if %s is selected as source", MAPPING_SOURCE_CERT_SUBJECTDN));

            ProviderConfigProperty firstNameMappingMethodList = new ProviderConfigProperty();
            firstNameMappingMethodList.setType(ProviderConfigProperty.LIST_TYPE);
            firstNameMappingMethodList.setName(X509ClientCertificateProvisioner.MAPPING_SOURCE_FIRSTNAME_SELECTION);
            firstNameMappingMethodList.setLabel("User First Name Source");
            firstNameMappingMethodList.setHelpText("Choose how to extract user's first name from the provided X.509 certificate");
            firstNameMappingMethodList.setDefaultValue(mappingSources[2]);
            firstNameMappingMethodList.setOptions(mappingSourceTypes);

            ProviderConfigProperty firstNameDnMapping = new ProviderConfigProperty();
            firstNameDnMapping.setType(ProviderConfigProperty.STRING_TYPE);
            firstNameDnMapping.setName(X509ClientCertificateProvisioner.MAPPING_SOURCE_FIRSTNAME_SELECTION_DN);
            firstNameDnMapping.setLabel("DN attribute for user's first name");
            firstNameDnMapping.setHelpText(String.format("An attribute of certificate's Distinguish Name (DN) from which to get user's first name. Required if %s is selected as source", MAPPING_SOURCE_CERT_SUBJECTDN));
            firstNameDnMapping.setDefaultValue("G");

            ProviderConfigProperty lastNameMappingMethodList = new ProviderConfigProperty();
            lastNameMappingMethodList.setType(ProviderConfigProperty.LIST_TYPE);
            lastNameMappingMethodList.setName(X509ClientCertificateProvisioner.MAPPING_SOURCE_LASTNAME_SELECTION);
            lastNameMappingMethodList.setLabel("User Last Name Source");
            lastNameMappingMethodList.setHelpText("Choose how to extract user's last name from the provided X.509 certificate");
            lastNameMappingMethodList.setDefaultValue(mappingSources[2]);
            lastNameMappingMethodList.setOptions(mappingSourceTypes);

            ProviderConfigProperty lastNameDnMapping = new ProviderConfigProperty();
            lastNameDnMapping.setType(ProviderConfigProperty.STRING_TYPE);
            lastNameDnMapping.setName(X509ClientCertificateProvisioner.MAPPING_SOURCE_LASTNAME_SELECTION_DN);
            lastNameDnMapping.setLabel("DN attribute for user's last name");
            lastNameDnMapping.setHelpText(String.format("An attribute of certificate's Distinguish Name (DN) from which to get user's last name. Required if %s is selected as source", MAPPING_SOURCE_CERT_SUBJECTDN));
            lastNameDnMapping.setDefaultValue("SN");

            configProperties = asList(emailMappingMethodList,
                emailDnMapping,
                firstNameMappingMethodList,
                firstNameDnMapping,
                lastNameMappingMethodList,
                lastNameDnMapping
            );
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Stream.concat(super.getConfigProperties().stream(), configProperties.stream())
            .toList();
    }

    @Override
    public String getHelpText() {
        return "Determine identity based on verified X.509 client certificate received as a part of mutual TLS handshake.";
    }

    @Override
    public String getDisplayType() {
        return "X509 User Provisioner";
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }


    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
