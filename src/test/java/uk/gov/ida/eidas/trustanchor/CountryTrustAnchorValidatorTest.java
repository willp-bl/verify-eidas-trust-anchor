package uk.gov.ida.eidas.trustanchor;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collection;

import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static com.nimbusds.jose.jwk.KeyOperation.VERIFY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CountryTrustAnchorValidatorTest {

    private CertificateValidator mockValidator = mock(CertificateValidator.class);
    private final CountryTrustAnchorValidator testValidator = new CountryTrustAnchorValidator(mockValidator);

    @BeforeEach
    public void setup() {
        when(mockValidator.checkCertificateValidity(any(), any())).thenReturn(ImmutableList.of());
    }

    @Test
    public void validTrustAnchorShouldRaiseNoExceptions(){
        RSAKey validTrustAnchor = getValidTrustAnchor();
        Collection<String> errors = testValidator.findErrors(validTrustAnchor);

        assertThat(errors).isEmpty();
    }

    private RSAKey getValidTrustAnchor() {
        RSAKey mockTrustAnchor = mock(RSAKey.class);
        when(mockTrustAnchor.getKeyID()).thenReturn("TestId");
        Base64 mockX509Cert = mock(Base64.class);
        when(mockTrustAnchor.getX509CertChain()).thenReturn(ImmutableList.of(mockX509Cert));
        when(mockTrustAnchor.getAlgorithm()).thenReturn(RS256);
        when(mockTrustAnchor.getKeyType()).thenReturn(KeyType.RSA);
        when(mockTrustAnchor.getKeyOperations()).thenReturn(ImmutableSet.of(VERIFY));

        return mockTrustAnchor;
    }
}
