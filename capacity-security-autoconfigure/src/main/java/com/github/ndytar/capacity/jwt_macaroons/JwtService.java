package com.github.ndytar.capacity.jwt_macaroons;
import com.github.ndytar.capacity.properties.CapacityJwtPropertie;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
import java.util.Set;

@Service
public class JwtService {

    private CapacityJwtPropertie jwtPropertie;
private  RevocationToken revocationToken;
private  ExtractionToken extractionToken;
    public JwtService(
            CapacityJwtPropertie jwtPropertie,
            RevocationToken revocationToken,
            ExtractionToken extractionToken) {
        this.jwtPropertie = jwtPropertie;

        this.revocationToken = revocationToken;
        this.extractionToken = extractionToken;
    }
    private SecretKey cleSignature() {
        byte[] cleBytes = Base64.getDecoder().decode(jwtPropertie.getKeysecret());
        return Keys.hmacShaKeyFor(cleBytes);
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
        String jwtId = extractionToken.extractJwtId(jwt);

        if (jwtId == null)
            return false;
        return revocationToken.revokeJwt(jwtId);
    }

    public boolean revokeAllJwt() {
        return revocationToken.revokeAllJwt();
    }

}