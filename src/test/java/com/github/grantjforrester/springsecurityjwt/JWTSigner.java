package com.github.grantjforrester.springsecurityjwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.Arrays;
import java.util.List;

import static com.nimbusds.jose.jwk.JWKSet.load;

/*
 * Creates signed JWTs from claims using keys from a key manager.
 *
 * See <a href="https://tools.ietf.org/html/rfc7515">RFC 7515: JSON Web Signature (JWS)</a>
 */
class JWTSigner {

    private static final Logger LOG = LoggerFactory.getLogger(JWTSigner.class);

    private static final List<JWSAlgorithm> MAC_ALGORITHMS = Arrays.asList(
            JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512
    );
    private static final List<JWSAlgorithm> ECDSA_ALGORITHMS = Arrays.asList(
            JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512
    );
    private static final List<JWSAlgorithm> RSASSA_ALGORITHMS = Arrays.asList(
            JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512,
            JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512
    );

    private final JWKSetManager keyManager;

    /*
     * Create a JWTSigner that uses keys from the given key manager.
     */
    JWTSigner(JWKSetManager keyManager) {
        LOG.trace("Parameters: keyManager={}", keyManager);
        if (keyManager == null) {
            throw new NullPointerException("keyManager cannot be null");
        }
        this.keyManager = keyManager;
        LOG.trace("Returning: none");
    }

    /*
     * Sign the claims with the given kid and returns the claims in the JWS compact serialized form.
     * The kid used is added as a JWT header claim 'kid'.
     */
    String sign(JWTClaimsSet claims, String kid) {
        LOG.trace("Parameters: claims={}, kid={}", claims, kid);
        try {
            JWK jwk = keyManager.getJWKByKid(kid);
            if (jwk == null) {
                throw new IllegalArgumentException("No such key with kid: " + kid);
            }

            JWSAlgorithm algorithm = JWSAlgorithm.parse(jwk.getAlgorithm().getName());
            JWSHeader header = new JWSHeader.Builder(algorithm).keyID(kid).build();
            SignedJWT signedJWT = new SignedJWT(header, claims);
            JWSSigner signer = getSigner(algorithm, jwk);
            signedJWT.sign(signer);
            String token = signedJWT.serialize();
            LOG.trace("Returning: {}", token);

            return token;
        } catch (JOSEException e) {
            throw new Error(e);
        }
    }

    /*
     * Get the appropriate signer based on the algorithm.
     */
    private JWSSigner getSigner(JWSAlgorithm algorithm, JWK jwk) {
        LOG.trace("Parameters: algorithm={}, key={}", algorithm, jwk);
        try {
            JWSSigner signer;
            if (MAC_ALGORITHMS.contains(algorithm)) {
                signer = new MACSigner((OctetSequenceKey) jwk);
            } else if (RSASSA_ALGORITHMS.contains(algorithm)) {
                signer = new RSASSASigner((RSAKey) jwk);
            } else if (ECDSA_ALGORITHMS.contains(algorithm)) {
                signer = new ECDSASigner((ECKey) jwk);
            } else {
                throw new IllegalArgumentException("Unsupported key algorithm: " + algorithm.getName());
            }
            LOG.trace("Returning: {}", signer);

            return signer;
        } catch (JOSEException e) {
            throw new Error(e);
        }
    }

    public static void main(String[] args) throws Exception {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("JWTSigner");

        URL url = JWTSigner.class.getResource("/testkeyset.jwks");
        File keySetFile = new File(url.toURI());
        JWKSetManager keysetManager = new JWKSetManager(load(keySetFile));
        JWTSigner signer = new JWTSigner(keysetManager);
        System.out.println("Keyset loaded");

        System.out.print("Enter claims: ");
        String claims = br.readLine();
        System.out.print("Enter key ID: ");
        String keyId = br.readLine();

        String jwt = signer.sign(JWTClaimsSet.parse(claims), keyId);
        System.out.println("JWT: " + jwt);

    }
}
