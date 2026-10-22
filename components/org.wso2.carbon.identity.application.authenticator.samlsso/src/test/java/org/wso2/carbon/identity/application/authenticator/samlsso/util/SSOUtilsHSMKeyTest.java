/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.samlsso.util;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.apache.commons.codec.binary.Base64;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.saml.common.util.SAMLInitializer;
import org.wso2.carbon.identity.saml.common.util.UnmarshallUtils;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Tests for signing federated SAML requests with an IS key held in an HSM.
 */
public class SSOUtilsHSMKeyTest {

    private static final String DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";

    private OpaqueRSAKeyTestProvider hsmProvider;

    @BeforeClass
    public void setUp() throws Exception {

        SAMLInitializer.doBootstrap();
        hsmProvider = new OpaqueRSAKeyTestProvider(2048);
    }

    @AfterMethod
    public void tearDown() {

        Security.removeProvider(hsmProvider.getName());
    }

    @Test
    public void testSignAuthnRequestWithHSMKey() throws Exception {

        // Registered after the JDK providers, like a SunPKCS11 token.
        Security.addProvider(hsmProvider);
        AuthnRequest request = buildAuthnRequest();

        SSOUtils.setSignature(request, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, DIGEST_SHA256, true,
                credential(hsmProvider.getPrivateKey()));

        assertTrue(verifies(request, hsmProvider.getPublicKey()));
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        assertFalse(verifies(request, generator.generateKeyPair().getPublic()));
    }

    @Test
    public void testSignRedirectQueryWithHSMKey() throws Exception {

        // HTTP-Redirect binding: the signature covers the query string, not the XML.
        Security.addProvider(hsmProvider);
        StringBuilder query = new StringBuilder("SAMLRequest=abc&RelayState=xyz");

        SSOUtils.addSignatureToHTTPQueryString(query, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256,
                credential(hsmProvider.getPrivateKey()));

        String signed = query.toString();
        int index = signed.indexOf("&Signature=");
        byte[] signatureValue = Base64.decodeBase64(URLDecoder.decode(signed.substring(index + 11),
                StandardCharsets.UTF_8.name()));
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(hsmProvider.getPublicKey());
        verifier.update(signed.substring(0, index).getBytes(StandardCharsets.UTF_8));
        assertTrue(verifier.verify(signatureValue));
    }

    private static X509Credential credential(PrivateKey privateKey) throws Exception {

        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getEncoded()).thenReturn(new byte[]{1, 2, 3});
        X509Credential credential = mock(X509Credential.class);
        when(credential.getPrivateKey()).thenReturn(privateKey);
        when(credential.getEntityCertificate()).thenReturn(certificate);
        return credential;
    }

    private static AuthnRequest buildAuthnRequest() {

        AuthnRequest request = (AuthnRequest) XMLObjectProviderRegistrySupport.getBuilderFactory()
                .getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME).buildObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
        request.setID("_" + System.nanoTime());
        Issuer issuer = (Issuer) XMLObjectProviderRegistrySupport.getBuilderFactory()
                .getBuilder(Issuer.DEFAULT_ELEMENT_NAME).buildObject(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue("https://localhost:9443/samlsso");
        request.setIssuer(issuer);
        return request;
    }

    /**
     * Verify like the external IdP: parse the serialized request again and check the signature in software.
     */
    private static boolean verifies(AuthnRequest signedRequest, PublicKey publicKey) throws Exception {

        AuthnRequest parsed = (AuthnRequest) UnmarshallUtils.unmarshall(
                SerializeSupport.nodeToString(signedRequest.getDOM()));
        new SAMLSignatureProfileValidator().validate(parsed.getSignature());
        try {
            SignatureValidator.validate(parsed.getSignature(), new BasicCredential(publicKey));
            return true;
        } catch (SignatureException e) {
            return false;
        }
    }
}
