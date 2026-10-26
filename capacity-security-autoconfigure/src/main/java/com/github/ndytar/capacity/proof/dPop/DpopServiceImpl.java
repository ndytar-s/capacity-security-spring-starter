package com.github.ndytar.capacity.proof.dPop;

import com.github.ndytar.capacity.properties.CapacityDpopPropertie;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;


@Slf4j
public class DpopServiceImpl implements  DpopService {

    private static final JOSEObjectType DPOP_TYP = new JOSEObjectType("dpop+jwt");
    private final JtiStore jtiStore;
    private final Duration iatWindow;
    private final Set<JWSAlgorithm> allowed;
    private final boolean isDpop;

    public DpopServiceImpl(JtiStore jtiStore, Duration iatWindow, CapacityDpopPropertie props) {
        this.jtiStore = jtiStore;
        this.iatWindow = iatWindow;
        this.allowed = props.getAlgorithms().stream()
                .map(JWSAlgorithm::parse).collect(Collectors.toUnmodifiableSet());
        this.isDpop = props.isActive();
        if (!Set.of(JWSAlgorithm.ES256, JWSAlgorithm.EdDSA).containsAll(allowed)) {
            throw new IllegalStateException("capacity.dpop.algorithms: only ES256 and EdDSA supported");
        }
        if (allowed.contains(JWSAlgorithm.EdDSA)) {
            try { Class.forName("com.google.crypto.tink.subtle.Ed25519Verify"); }
            catch (ClassNotFoundException e) {
                throw new IllegalStateException("EdDSA enabled but Tink is missing from the classpath");
            }
        }
    }

    // Au login : transforme la JWK publique du client en claim cnf
    @Override
    public Map<String, Object> buildCnf(String jwkJson) {
        if (!isDpop) return null;
        try {
            JWK jwk = JWK.parse(jwkJson);
            checkKey(jwk);
            return Map.of("jkt", jwk.computeThumbprint().toString());
        } catch (ParseException | JOSEException e) {
            throw new BadCredentialsException("Invalid public key", e);
        }
    }

    private void checkKey(JWK jwk) {
        if (jwk.isPrivate()) throw new BadCredentialsException("Public key required");
        boolean ok =
                (jwk instanceof ECKey ec && Curve.P_256.equals(ec.getCurve())
                        && allowed.contains(JWSAlgorithm.ES256))
                        || (jwk instanceof OctetKeyPair okp && Curve.Ed25519.equals(okp.getCurve())
                        && allowed.contains(JWSAlgorithm.EdDSA));
        if (!ok) throw new BadCredentialsException("Unsupported key type or curve");
    }

    @Override
    public DpopProof extractDpopProof(HttpServletRequest request) {
       String raw = request.getHeader("DPoP");
        System.out.println("------extractDpopProof brut: " + raw);
        if (raw == null || raw.isBlank()) throw new BadCredentialsException("Missing DPoP header");
        try {
            SignedJWT jwt = SignedJWT.parse(raw);
            JWSHeader h = jwt.getHeader();
            if (!DPOP_TYP.equals(h.getType())) throw new BadCredentialsException("Bad typ");
            System.out.println("------extractDpopProof jwt : " + jwt.toString());
            if (!allowed.contains(h.getAlgorithm())) throw new BadCredentialsException("Algorithm not allowed");
            JWK jwk = h.getJWK();
            if (jwk == null) throw new BadCredentialsException("Missing jwk in DPoP header");
            checkKey(jwk);

            JWTClaimsSet c = jwt.getJWTClaimsSet();
            Date iat = c.getIssueTime();
            log.info("iat instant : {}, htm : {}, htu: {}", iat, jwt.toString(), jwt.getHeader().toString());
            log.info("current instant: {}", Instant.now().toString());
            return new DpopProof(jwt, jwk, c.getJWTID(),
                    iat == null ? null : iat.toInstant(),
                    c.getStringClaim("htm"), c.getStringClaim("htu"), c.getStringClaim("chash"));
        } catch (ParseException e) {
            throw new BadCredentialsException("Malformed DPoP proof", e);
        }
    }

    // 1) la clé du proof est bien celle liée à la capacité  2) la signature est valide
    @Override
    public boolean verifySignature(DpopProof proof, String expectedJkt) {
        try {
            String actual = proof.jwk().computeThumbprint().toString();
            if (expectedJkt == null)
              throw new BadCredentialsException("Missing capacity don't provide JWK ");
            log.info("DPoP: jkt actual={}, expected={}", actual, expectedJkt);
            if (!MessageDigest.isEqual(actual.getBytes(UTF_8), expectedJkt.getBytes(UTF_8))) return false;

            JWSAlgorithm alg = proof.jwt().getHeader().getAlgorithm();
            System.out.println("------verifySignature: " + alg);
            JWSVerifier verifier;
            if (JWSAlgorithm.ES256.equals(alg) && proof.jwk() instanceof ECKey ec) {
                verifier = new ECDSAVerifier(ec);
            } else if (JWSAlgorithm.EdDSA.equals(alg) && proof.jwk() instanceof OctetKeyPair okp) {
                verifier = new Ed25519Verifier(okp);
            } else {
                return false; // algo et type de clé incohérents
            }
            System.out.println("------verifySignature: " + proof.jwt().verify(verifier));
            return proof.jwt().verify(verifier);
        } catch (JOSEException e) {
            return false;
        }
    }

    @Override
    public boolean verifyPayload(DpopProof proof, HttpServletRequest request, String capacityToken) {
        if (proof.jti() == null || proof.iat() == null){
            log.warn("---------tti or iat is nullr-------------");
            return false;
        }
        if (!request.getMethod().equalsIgnoreCase(proof.htm())){
            log.warn("----------htm method unavailable-------------");
            return false;
        }
        if (!request.getRequestURL().toString().equals(proof.htu())){
            log.warn("----------htu method unavailable-------------");
            return false;
        }

        Instant now = Instant.now();
        if (proof.iat().isBefore(now.minus(iatWindow)) || proof.iat().isAfter(now.plusSeconds(5))){
            log.warn("----------iat is before now (time)-------------");
            return false;
        }

        if (proof.chash() != null && !sha256(capacityToken).equals(proof.chash())){
            log.warn("----------chash is before now -------------");
            return false;
        }

        return jtiStore.tryRegister(proof.jti(), iatWindow);
    }


    private String sha256(String v) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(v.getBytes(UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(d);
        } catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
}
