package com.github.ndytar.capacity.jwt_macaroons;

import com.github.ndytar.capacity.audit.AuditCollector;
import com.github.ndytar.capacity.audit.AuditEvent;
import com.github.ndytar.capacity.audit.AuditResult;
import com.github.ndytar.capacity.customclaims.CustomClaimsContextHolder;
import com.github.ndytar.capacity.exception.InvalidTokenException;
import com.github.ndytar.capacity.properties.CapacityJwtPropertie;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.Set;

@Slf4j
public class JwtService {

    private final CapacityJwtPropertie jwtPropertie;
    private final RevocationToken revocationToken;
    private final ExtractionToken extractionToken;
    private final RegistrationToken registrationToken;
    private final AuditCollector auditCollector;
    public JwtService(
            CapacityJwtPropertie jwtPropertie,
            RevocationToken revocationToken,
                      ExtractionToken extractionToken,
            RegistrationToken registrationToken,
            AuditCollector auditCollector
    ) {

        this.jwtPropertie = jwtPropertie;

        this.revocationToken = revocationToken;
        this.extractionToken = extractionToken;
        this.registrationToken = registrationToken;

        this.auditCollector = auditCollector;
    }
    private SecretKey cleSignature() {
       try {
        byte[] cleBytes = Base64.getDecoder().decode(jwtPropertie.getKeysecret());
        return Keys.hmacShaKeyFor(cleBytes);
    } catch (IllegalArgumentException e) {
           auditCollector.record(
                   new AuditEvent(Instant.now(), "Decode key jwt", null, null,
                           AuditResult.FAILURE,
                           e.getMessage()
                   ));
        throw new IllegalStateException("The configured token signing key is invalid", e);
    }
    }
    public String generer(String scope,boolean personnel, Long id,  Set<String> actions,
                          boolean oneTime,  Map<String,Object> publicKey,
                          String uuid, Map<String, String> customClaims) {
        CustomClaimsContextHolder.clear();
        //System.out.println("------------view jkt :"+publicKey.get("jkt"));
        return Jwts.builder()
                .claim("subject_id",id)
                .claim("personnel",personnel)
                .claim("scope", scope)
                .claim("actions", actions)
                .claim("one_time", oneTime)
                .claim("jkt",publicKey != null ? publicKey.get("jkt") : null)
                .claim("uuid", uuid)
                .claim("customClaims", customClaims)
                .issuedAt(new Date())
                .expiration(new Date(
                        System.currentTimeMillis() + jwtPropertie.getDuration()))
                .signWith(cleSignature())
                .compact();
    }
    public boolean revokeJwt(String jwt) {

        if (jwt == null || jwt.isEmpty()) {
            auditCollector.record(
                    new AuditEvent(Instant.now(), "is token", null, null,
                            AuditResult.FAILURE,
                           "INVALID_TOKEN, Null token not acceptable"
                    ));
            throw new InvalidTokenException("INVALID_TOKEN,"," Null token not acceptable",null);
        }

        String jwtId = extractionToken.extractJwtId(jwt);

        if (jwtId == null)
            return false;
        return revocationToken.revokeJwt(jwtId);
    }

    public boolean revokeAllJwt() {

        return revocationToken.revokeAllJwt();
    }
   public void isJwtRedis(String jwt)  {
       String jwtId = extractionToken.extractJwtId(jwt);
       if (!registrationToken.existsJwt(jwtId)) {
           auditCollector.record(
                   new AuditEvent(Instant.now(), "is token in redis", null, null,
                           AuditResult.FAILURE,
                           "Token invalid or expired/revoked!"
                   ));
           throw new BadCredentialsException("Token invalid or expired/revoked! ");
       }
   }


}