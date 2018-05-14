package uk.gov.ida.eidas.trustanchor;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

class JwkValidator {
    static Collection<String> checkCertificateValidity(JWK anchor) {
        List<String> errors = new ArrayList<>();
        Base64X509CertificateDecoder decoder;
        try {
            decoder = new Base64X509CertificateDecoder();
        } catch (CertificateException e) {
            errors.add(String.format("X.509 certificate factory not available: %s", e.getMessage()));
            return errors;
        }

        X509Certificate x509Certificate;
        try {
            x509Certificate = decoder.decodeX509(anchor.getX509CertChain().get(0));
        } catch (CertificateException e) {
            errors.add(String.format("Unable to decode x509 Certificate: %s", e.getMessage()));
            return errors;
        }

        try {
            boolean certDoesntMatchPublicKey = certDoesntMatchPublicKey((RSAKey) anchor, x509Certificate);
            if (certDoesntMatchPublicKey) {
                errors.add("X.509 Certificate does not match the public key");
            }
        } catch (JOSEException e) {
            errors.add(String.format("Error getting public key from trust anchor: %s", e.getMessage()));
            return errors;
        }

        errors.addAll(validateCertChain(decoder, x509Certificate, anchor.getX509CertChain()));

        return errors;
    }

    private static boolean certDoesntMatchPublicKey(RSAKey anchor, X509Certificate x509Certificate) throws JOSEException {
        return !x509Certificate.getPublicKey().equals(anchor.toPublicKey());
    }

    private static List<String> validateCertChain(Base64X509CertificateDecoder decoder, X509Certificate x509Certificate, List<Base64> x509CertChain) {
        List<String> chainErrors = new ArrayList<>();
        X509Certificate signedCert = x509Certificate;
        for (Base64 base64cert : x509CertChain) {
            X509Certificate signingCert;
            try {
                signingCert = decoder.decodeX509(base64cert);
            } catch (CertificateException e) {
                chainErrors.add(String.format("Unable to decode certificate %s: %s", base64cert, e.getMessage()));

                //TODO Should this be a return? i.e. do we stop everything if we can't decode a cert in the chain?
                continue;
            }

            List<String> certErrors = validateCert(signingCert);
            chainErrors.addAll(certErrors);

            List<String> signatureErrors = verifySignature(signedCert, signingCert);
            chainErrors.addAll(signatureErrors);

            signedCert = signingCert;
        }

        chainErrors.addAll(verifySignature(signedCert, signedCert));

        return chainErrors;
    }

    private static List<String> validateCert(X509Certificate signingCert) {
        List<String> certErrors = new ArrayList<>();
        try {
            signingCert.checkValidity();
        } catch (CertificateExpiredException e) {
            certErrors.add(String.format("Certificate %s is no longer valid: %s",
                    signingCert.getSubjectX500Principal(), e.getMessage())
            );
        } catch (CertificateNotYetValidException e) {
            certErrors.add(String.format("Certificate %s is not yet valid: %s",
                    signingCert.getSubjectX500Principal(), e.getMessage())
            );
        }

        return certErrors;
    }

    private static List<String> verifySignature(X509Certificate signedCert, X509Certificate signingCert) {
        List<String> signatureErrors = new ArrayList<>();
        try {
            signedCert.verify(signingCert.getPublicKey());
        } catch (CertificateException e) {
            signatureErrors.add(String.format("Unable to ensure that cert %s is signed by cert %s : %s",
                    signedCert.getSubjectX500Principal(),
                    signingCert.getSubjectX500Principal(),
                    e.getMessage())
            );
        } catch (NoSuchAlgorithmException e) {
            signatureErrors.add(String.format("Could not find algorithm %s", e.getMessage()));
        } catch (InvalidKeyException e) {
            signatureErrors.add(String.format("Cert %s is not signed by parent in chain cert %s : %s",
                    signedCert.getSubjectX500Principal(),
                    signingCert.getSubjectX500Principal(),
                    e.getMessage())
            );
        } catch (SignatureException e) {
            signatureErrors.add(String.format("Invalid signature for cert %s: %s",
                    signedCert.getSubjectX500Principal(),
                    e.getMessage())
            );
        } catch (NoSuchProviderException e) {
            signatureErrors.add(String.format("Unable to validate cert chain as unable to locate security provider: %s",
                    e.getMessage())
            );
        }
        return signatureErrors;
    }
}
