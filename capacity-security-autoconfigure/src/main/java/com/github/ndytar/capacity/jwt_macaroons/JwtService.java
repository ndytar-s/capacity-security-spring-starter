package com.github.ndytar.capacity.jwt_macaroons;
import  com.github.ndytar.capacity.exception.InvalidTokenException;
import  com.github.ndytar.capacity.properties.CapacityJwtPropertie;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.BadCredentialsException;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
import java.util.Set;

public class JwtService {

    private final CapacityJwtPropertie jwtPropertie;
    private final RevocationToken revocationToken;
    private final ExtractionToken extractionToken;
    private final RegistrationToken registrationToken;
    public JwtService(
            CapacityJwtPropertie jwtPropertie,
            RevocationToken revocationToken,
            ExtractionToken extractionToken,
            RegistrationToken registrationToken) {
        this.jwtPropertie = jwtPropertie;

        this.revocationToken = revocationToken;
        this.extractionToken = extractionToken;
        this.registrationToken = registrationToken;
    }
    private SecretKey cleSignature() {
       try {
        byte[] cleBytes = Base64.getDecoder().decode(jwtPropertie.getKeysecret());
        return Keys.hmacShaKeyFor(cleBytes);
    } catch (IllegalArgumentException e) {
        throw new IllegalStateException("The configured token signing key is invalid", e);
    }
    }
    public String generer(String scope, Set<String> actions,
                          boolean oneTime,  String deviceId,
                          String uuid) {

        return Jwts.builder()
                .claim("scope",      scope)
                .claim("actions",    actions)
                .claim("one_time",   oneTime)
                .claim("deviceId",      deviceId)
                .claim("uuid",        uuid)
                .issuedAt(new Date())
                .expiration(new Date(
                        System.currentTimeMillis() + jwtPropertie.getDuration()))
                .signWith(cleSignature())
                .compact();
    }
    public boolean revokeJwt(String jwt) {

        if (jwt == null || jwt.isEmpty())
            throw new InvalidTokenException("INVALID_TOKEN,"," Null token not acceptable",null);

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
       if (!registrationToken.existsJwt(jwtId))
           throw new BadCredentialsException("Token invalid or expired/revoked! ");
   }
}