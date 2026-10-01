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

import org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticatorFactory;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;

/**
 * @author <a href="mailto:tomasz@polachowski.pl">Tomasz Polachowski</a>
 * @version $Revision: 1 $
 *
 */
public class X509ClientCertificateProvisionerFactory extends AbstractX509ClientCertificateAuthenticatorFactory {

    public static final String PROVIDER_ID = "auth-x509-client-cert-provisioner";
    public static final X509ClientCertificateProvisioner SINGLETON =
            new X509ClientCertificateProvisioner();


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
