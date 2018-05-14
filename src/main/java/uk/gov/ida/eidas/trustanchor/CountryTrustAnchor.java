package uk.gov.ida.eidas.trustanchor;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;

import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CountryTrustAnchor {

  public static JWK make(List<X509Certificate> certificates, String keyId) {
      Stream<X509Certificate> stream = certificates.stream();
      List<PublicKey> invalidPublicKeys = stream
            .map(X509Certificate::getPublicKey)
            .filter(key -> !(key instanceof RSAPublicKey))
            .collect(Collectors.toList());

    if (!invalidPublicKeys.isEmpty()) {
      throw new RuntimeException(String.format(
        "Certificate public key(s) in wrong format, got %s, expecting %s",
        String.join(" ", invalidPublicKeys.stream().map(key -> key.getClass().getName()).collect(Collectors.toList())),
        RSAPublicKey.class.getName()));
    }

    RSAPublicKey publicKey = (RSAPublicKey) certificates.get(0).getPublicKey();

      List<X509Certificate> sortedCerts = CertificateSorter.sort(certificates);
      List<Base64> encodedSortedCertChain = sortedCerts.stream()
              .map(certificate -> {
      try {
        return Base64.encode(certificate.getEncoded());
      } catch (CertificateEncodingException e) {
        throw new RuntimeException(e);
      }
    }).collect(Collectors.toList());

    JWK key = new RSAKey.Builder(publicKey)
      .algorithm(JWSAlgorithm.RS256)
      .keyOperations(Collections.singleton(KeyOperation.VERIFY))
      .keyID(keyId)
      .x509CertChain(encodedSortedCertChain)
      .build();

    Collection<String> errors = findErrors(key);
    if (!errors.isEmpty()) {
      throw new Error(String.format("Managed to generate an invalid anchor: %s", String.join(", ", errors)));
    }

    return key;
  }

    public static JWK parse(String json) throws ParseException {
    JWK key = JWK.parse(json);

    Collection<String> errors = findErrors(key);
    if (!errors.isEmpty()) {
      throw new ParseException(String.format("JWK was not a valid trust anchor: %s", String.join(", ", errors)), 0);
    }

    return key;
  }

  public static Collection<String> findErrors(JWK anchor) {
    Collection<String> errors = new HashSet<>();

    if (!isKeyTypeRSA(anchor)) {
      errors.add(String.format("Expecting key type to be %s, was %s", KeyType.RSA, anchor.getKeyType()));
    }
    if (!isAlgorithmRS256(anchor)) {
      errors.add(String.format("Expecting algorithm to be %s, was %s", JWSAlgorithm.RS256, anchor.getAlgorithm()));
    }
    if (!isKeyOperationsVerify(anchor)) {
      errors.add(String.format("Expecting key operations to only contain %s", KeyOperation.VERIFY));
    }
    if (!isKeyIDPresent(anchor)) {
      errors.add("Expecting a KeyID");
    }

      if (hasCertificates(anchor)) {
        errors.addAll(JwkValidator.checkCertificateValidity(anchor));
      } else {
        errors.add("Expecting at least one X.509 certificate");
      }

      return errors;
  }

    private static boolean isKeyTypeRSA(JWK anchor){
	return Optional.ofNullable(anchor.getKeyType())
			.map(type -> type.equals(KeyType.RSA))
			.orElse(false);
  }

  private static boolean isAlgorithmRS256(JWK anchor){
	return Optional.ofNullable(anchor.getAlgorithm())
			.map(alg -> alg.equals(JWSAlgorithm.RS256))
			.orElse(false);
  }

  private static boolean isKeyOperationsVerify(JWK anchor){
    return Optional.ofNullable(anchor.getKeyOperations())
    		.filter(ops -> ops.size() == 1)
    		.map(ops -> ops.contains(KeyOperation.VERIFY))
    		.orElse(false);
  }

  private static boolean isKeyIDPresent(JWK anchor){
    return Optional.ofNullable(anchor.getKeyID())
    		.map(kid -> !kid.isEmpty())
    		.orElse(false);
  }

  private static boolean hasCertificates(JWK anchor){
    return Optional.ofNullable(anchor.getX509CertChain())
    		.map(certChain -> certChain.size() > 0)
    		.orElse(false);
  }

}
