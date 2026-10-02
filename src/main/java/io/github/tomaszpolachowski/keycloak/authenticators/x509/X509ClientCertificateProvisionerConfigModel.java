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

import static org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator.MAPPING_SOURCE_CERT_SUBJECTALTNAME_OTHERNAME;
import static org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator.MAPPING_SOURCE_CERT_SUBJECTDN;

import org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel;

/**
 * @author <a href="mailto:tomasz@polachowski.pl">Tomasz Polachowski</a>
 * @version $Revision: 1 $
 *
 */
public class X509ClientCertificateProvisionerConfigModel extends X509AuthenticatorConfigModel {
    
    public X509ClientCertificateProvisionerConfigModel(X509AuthenticatorConfigModel model) {
        super(model);
    }

    public X509ClientCertificateProvisionerConfigModel() {
    }

    public MappingSourceType getMappingSourceEmailType() {
        return MappingSourceType.parse(getConfig().getOrDefault(X509ClientCertificateProvisioner.MAPPING_SOURCE_EMAIL_SELECTION, MAPPING_SOURCE_CERT_SUBJECTALTNAME_OTHERNAME));
    }

    public String getMappingSourceEmailDn() {
        return getConfig().getOrDefault(X509ClientCertificateProvisioner.MAPPING_SOURCE_EMAIL_SELECTION_DN, "");
    }

    public MappingSourceType getMappingSourceFirstNameType() {
        return MappingSourceType.parse(getConfig().getOrDefault(X509ClientCertificateProvisioner.MAPPING_SOURCE_FIRSTNAME_SELECTION, MAPPING_SOURCE_CERT_SUBJECTDN));
    }

    public String getMappingSourceFirstNameDn() {
        return getConfig().getOrDefault(X509ClientCertificateProvisioner.MAPPING_SOURCE_FIRSTNAME_SELECTION_DN, "G");
    }

    public MappingSourceType getMappingSourceLastNameType() {
        return MappingSourceType.parse(getConfig().getOrDefault(X509ClientCertificateProvisioner.MAPPING_SOURCE_LASTNAME_SELECTION, MAPPING_SOURCE_CERT_SUBJECTDN));
    }

    public String getMappingSourceLastNameDn() {
        return getConfig().getOrDefault(X509ClientCertificateProvisioner.MAPPING_SOURCE_LASTNAME_SELECTION_DN, "SN");
    }
}
