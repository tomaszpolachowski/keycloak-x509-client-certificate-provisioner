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

import java.lang.module.ModuleDescriptor.Version;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.security.auth.x500.X500Principal;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator;
import org.keycloak.authentication.authenticators.x509.CertificateValidator;
import org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.UserIdentityExtractor;
import org.keycloak.common.crypto.UserIdentityExtractorProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.ServicesLogger;


import org.jboss.logging.Logger;

import static org.keycloak.authentication.authenticators.util.AuthenticatorUtils.getDisabledByBruteForceEventError;
import static org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator.MAPPING_SOURCE_CERT_SUBJECTALTNAME_EMAIL;
import static org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator.MAPPING_SOURCE_CERT_SUBJECTALTNAME_OTHERNAME;
import static org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator.MAPPING_SOURCE_CERT_SUBJECTDN;
import static org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel.MappingSourceType;

/**
 * @author <a href="mailto:tomasz@polachowski.pl">Tomasz Polachowski</a>
 * @version $Revision: 1 $
 *
 */
public class X509ClientCertificateProvisioner extends AbstractX509ClientCertificateAuthenticator {

    private final static Logger logger = Logger.getLogger(X509ClientCertificateProvisioner.class);

    private static final Map<String, String> CUSTOM_OIDS = Map.of(
            "2.5.4.5", "serialNumber".toUpperCase(Locale.ROOT),
            "2.5.4.15", "businessCategory".toUpperCase(Locale.ROOT),
            "1.3.6.1.4.1.311.60.2.1.3", "jurisdictionCountryName".toUpperCase(Locale.ROOT),
            "1.2.840.113549.1.9.1", "emailAddress".toUpperCase(Locale.ROOT));

    public static final String MAPPING_SOURCE_EMAIL_SELECTION = "x509-cert-auth.mapping-source-selection.email";
    public static final String MAPPING_SOURCE_EMAIL_SELECTION_DN = "x509-cert-auth.mapping-source-selection.email.dn";
    public static final String MAPPING_SOURCE_FIRSTNAME_SELECTION = "x509-cert-auth.mapping-source-selection.firstname";
    public static final String MAPPING_SOURCE_FIRSTNAME_SELECTION_DN = "x509-cert-auth.mapping-source-selection.firstname.dn";
    public static final String MAPPING_SOURCE_LASTNAME_SELECTION = "x509-cert-auth.mapping-source-selection.lastname";
    public static final String MAPPING_SOURCE_LASTNAME_SELECTION_DN = "x509-cert-auth.mapping-source-selection.lastname.dn";

    @Override
    public void close() {

    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {

        try {
            boolean checkCASubjectDN = true;
            try {
                Version currentVersion = Version.parse(System.getProperty("kc.version"));
                Version expectedVersion = Version.parse("26.8.0");
                if (currentVersion.compareTo(expectedVersion) < 0) {
                    checkCASubjectDN = false;
                }
            } catch (IllegalArgumentException e) {
                checkCASubjectDN = false;
            }

            KeycloakSession session = context.getSession();
            RealmModel realm = context.getRealm();

            dumpContainerAttributes(context);

            X509Certificate[] certs = getCertificateChain(context);
            if (certs == null || certs.length == 0) {
                // No x509 client cert, fall through and
                // continue processing the rest of the authentication flow
                logger.debug("[authenticate] x509 client certificate is not available for mutual SSL.");
                context.attempted();
                return;
            }

            saveX509CertificateAuditDataToAuthSession(context, certs[0]);
            recordX509CertificateAuditDataViaContextEvent(context);

            X509ClientCertificateProvisionerConfigModel config = null;
            if (context.getAuthenticatorConfig() != null && context.getAuthenticatorConfig().getConfig() != null) {
                config = new X509ClientCertificateProvisionerConfigModel((X509AuthenticatorConfigModel)context.getAuthenticatorConfig());
            }
            if (config == null) {
                logger.warn("[authenticate] x509 Client Certificate Authentication configuration is not available.");
                context.challenge(createInfoResponse(context, "X509 client authentication has not been configured yet"));
                context.attempted();
                return;
            }

            if (checkCASubjectDN && config.getCASubjectDN().isEmpty()) {
                logger.warnf("[authenticate] Option '%s' is empty, this configuration is deprecated, please configure it for the authenticator in realm '%s'",
                        CERTIFICATE_CA_SUBJECT_DN, realm.getName());
            }

            // Validate X509 client certificate
            try {
                CertificateValidator.CertificateValidatorBuilder builder = certificateValidationParameters(session, config);
                CertificateValidator validator = builder.build(certs);
                PKIXCertPathBuilderResult certPathBuilderResult = validator.validateTrust().getCertPathBuilderResult();
                X509Certificate certificate = certPathBuilderResult.getTrustAnchor().getTrustedCert();
                X500Principal principal = certificate.getSubjectX500Principal();
                String dn = principal.getName(X500Principal.RFC2253, CUSTOM_OIDS);
                logger.infof("[authenticate] Issuer DN is '%s'", dn);
                if (checkCASubjectDN) {
                    validator
                        .validateCASubjectDN()
                        .validateTimestamps()
                        .validateKeyUsage()
                        .validateExtendedKeyUsage()
                        .validatePolicy()
                        .checkRevocationStatus();
                } else {
                    validator.validateTrust()
                        .validateTimestamps()
                        .validateKeyUsage()
                        .validateExtendedKeyUsage()
                        .validatePolicy()
                        .checkRevocationStatus();
                }
            } catch(Exception e) {
                logger.error(e.getMessage(), e);
                // TODO use specific locale to load error messages
                String errorMessage = "Certificate validation's failed.";
                // TODO is calling form().setErrors enough to show errors on login screen?
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(),
                        errorMessage, "Certificate revoked or incorrect."));
                context.attempted();
                return;
            }

            Object userIdentity = getUserIdentityExtractor(config).extractUserIdentity(certs);
            if (userIdentity == null) {
                context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
                logger.warnf("[authenticate] Unable to extract user identity from certificate.");
                // TODO use specific locale to load error messages
                String errorMessage = "Unable to extract user identity from specified certificate";
                // TODO is calling form().setErrors enough to show errors on login screen?
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(), errorMessage));
                context.attempted();
                return;
            }

            String username = userIdentity.toString();
            if (username == null || username.trim().isEmpty()) {
                context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
                logger.warnf("[authenticate] Unable to extract username from certificate.");
                // TODO use specific locale to load error messages
                String errorMessage = "Unable to extract username from specified certificate";
                // TODO is calling form().setErrors enough to show errors on login screen?
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(), errorMessage));
                context.attempted();
                return;
            }

            UserModel user;
            try {
                context.getEvent().detail(Details.USERNAME, username);
                context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, username);
                user = getUserIdentityToModelMapper(config).find(context, userIdentity);
            }
            catch(ModelDuplicateException e) {
                ServicesLogger.LOGGER.modelDuplicateException(e);
                String errorMessage = "X509 certificate authentication's failed.";
                // TODO is calling form().setErrors enough to show errors on login screen?
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(),
                        errorMessage, e.getMessage()));
                context.attempted();
                return;
            }

            if (user == null) {
                // add user if not yet exists
                if (AuthenticatorUtils.isUsernameTooLong(username)) {
                    context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
                    logger.warnf("[authenticate] Username too long.");
                    // TODO use specific locale to load error messages
                    String errorMessage = "Username too long";
                    // TODO is calling form().setErrors enough to show errors on login screen?
                    context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(), errorMessage));
                    context.attempted();
                    return;
                }
                UserIdentityExtractorProvider userDataExtractorProvider = CryptoIntegration.getProvider().getIdentityExtractorProvider();
                UserIdentityExtractor emailExtractor = switch (config.getMappingSourceEmailType()) {
                    case SUBJECTALTNAME_EMAIL -> userDataExtractorProvider.getSubjectAltNameExtractor(1);
                    case SUBJECTALTNAME_OTHERNAME -> userDataExtractorProvider.getSubjectAltNameExtractor(0);
                    case SUBJECTDN -> userDataExtractorProvider.getX500NameExtractor(config.getMappingSourceEmailDn(), c -> c[0].getSubjectX500Principal());
                    default -> null;
                };
                UserIdentityExtractor firstNameExtractor = switch (config.getMappingSourceFirstNameType()) {
                    case SUBJECTALTNAME_EMAIL -> userDataExtractorProvider.getSubjectAltNameExtractor(1);
                    case SUBJECTALTNAME_OTHERNAME -> userDataExtractorProvider.getSubjectAltNameExtractor(0);
                    case SUBJECTDN -> userDataExtractorProvider.getX500NameExtractor(config.getMappingSourceFirstNameDn(), c -> c[0].getSubjectX500Principal());
                    default -> null;
                };
                UserIdentityExtractor lastNameExtractor = switch (config.getMappingSourceLastNameType()) {
                    case SUBJECTALTNAME_EMAIL -> userDataExtractorProvider.getSubjectAltNameExtractor(1);
                    case SUBJECTALTNAME_OTHERNAME -> userDataExtractorProvider.getSubjectAltNameExtractor(0);
                    case SUBJECTDN -> userDataExtractorProvider.getX500NameExtractor(config.getMappingSourceLastNameDn(), c -> c[0].getSubjectX500Principal());
                    default -> null;
                };
                Object emailParameter = null, firstNameParameter = null, lastNameParameter = null;
                if (emailExtractor != null && firstNameExtractor != null && lastNameExtractor != null) {
                    emailParameter = emailExtractor.extractUserIdentity(certs);
                    firstNameParameter = firstNameExtractor.extractUserIdentity(certs);
                    lastNameParameter = lastNameExtractor.extractUserIdentity(certs);
                }
                String email = null, firstName = null, lastName = null;
                if (emailParameter != null && firstNameParameter != null && lastNameParameter != null)
                {
                    email = emailParameter.toString();
                    firstName = firstNameParameter.toString();
                    lastName = lastNameParameter.toString();
                }
                if (email != null && !email.isBlank() && firstName != null && !firstName.isBlank() && lastName != null && !lastName.isBlank())
                {
                    user = session.users().addUser(realm, username);
                    user.setEmail(email);
                    user.setFirstName(firstName);
                    user.setLastName(lastName);
                }
                if (user != null) {
                    user.setEmailVerified(true);
                    user.setEnabled(true);
                }
            }

            if (user == null) {
                // TODO use specific locale to load error messages
                String errorMessage = "X509 certificate authentication's failed.";
                // TODO is calling form().setErrors enough to show errors on login screen?
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(),
                        errorMessage, "Invalid user"));
                context.attempted();
                return;
            }

            String bruteForceError = getDisabledByBruteForceEventError(context, user);
            if (bruteForceError != null) {
                context.getEvent().user(user);
                context.getEvent().error(bruteForceError);
                // TODO use specific locale to load error messages
                String errorMessage = "X509 certificate authentication's failed.";
                // TODO is calling form().setErrors enough to show errors on login screen?
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(),
                        errorMessage, "Invalid user"));
                context.attempted();
                return;
            }

            if (!userEnabled(context, user)) {
                // TODO use specific locale to load error messages
                String errorMessage = "X509 certificate authentication's failed.";
                // TODO is calling form().setErrors enough to show errors on login screen?
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(),
                        errorMessage, "User is disabled"));
                context.attempted();
                return;
            }
            context.setUser(user);

            // Check whether to display the identity confirmation
            if (!config.getConfirmationPageDisallowed()) {
                // Calling forceChallenge was the only way to display
                // a form to let users either choose the user identity from certificate
                // or to ignore it and proceed to a normal login screen. Attempting
                // to call the method "challenge" results in a wrong/unexpected behavior.
                context.forceChallenge(createSuccessResponse(context, certs[0].getSubjectDN().toString()));
                // Do not set the flow status yet, we want to display a form to let users
                // choose whether to accept the identity from certificate or to specify username/password explicitly
            }
            else {
                // Bypass the confirmation page and log the user in
                context.success(UserCredentialModel.CLIENT_CERT);
            }
        }
        catch(Exception e) {
            logger.errorf(e, "[authenticate] Exception: %s", e.getMessage());
            context.attempted();
        }
    }

    private Response createErrorResponse(AuthenticationFlowContext context,
                                         String subjectDN,
                                         String errorMessage,
                                         String ... errorParameters) {

        return createResponse(context, subjectDN, false, errorMessage, errorParameters);
    }

    private Response createSuccessResponse(AuthenticationFlowContext context,
                                           String subjectDN) {
        return createResponse(context, subjectDN, true, null, null);
    }

    private Response createResponse(AuthenticationFlowContext context,
                                         String subjectDN,
                                         boolean isUserEnabled,
                                         String errorMessage,
                                         Object[] errorParameters) {

        LoginFormsProvider form = context.form();
        if (errorMessage != null && errorMessage.trim().length() > 0) {
            List<FormMessage> errors = new LinkedList<>();

            errors.add(new FormMessage(errorMessage));
            if (errorParameters != null) {

                for (Object errorParameter : errorParameters) {
                    if (errorParameter == null) continue;
                    for (String part : errorParameter.toString().split("\n")) {
                        errors.add(new FormMessage(part));
                    }
                }
            }
            form.setErrors(errors);
        }

        MultivaluedMap<String,String> formData = new MultivaluedHashMap<>();
        formData.add("username", context.getUser() != null ? context.getUser().getUsername() : "unknown user");
        formData.add("subjectDN", subjectDN);
        formData.add("isUserEnabled", String.valueOf(isUserEnabled));

        form.setFormData(formData);

        return form.createX509ConfirmPage();
    }

    private void dumpContainerAttributes(AuthenticationFlowContext context) {

        Map<String, Object> attributeNames = context.getSession().getAttributes();
        for (String name : attributeNames.keySet()) {
            logger.tracef("[dumpContainerAttributes] \"%s\"", name);
        }
    }

    private boolean userEnabled(AuthenticationFlowContext context, UserModel user) {
        if (!user.isEnabled()) {
            context.getEvent().user(user);
            context.getEvent().error(Errors.USER_DISABLED);
            return false;
        }
        return true;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.clearUser();
            context.attempted();
            return;
        }
        if (context.getUser() != null) {
            recordX509CertificateAuditDataViaContextEvent(context);
            context.success(UserCredentialModel.CLIENT_CERT);
            return;
        }
        context.attempted();
    }
}