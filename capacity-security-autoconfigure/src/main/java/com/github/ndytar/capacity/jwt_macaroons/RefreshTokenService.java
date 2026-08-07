package com.github.ndytar.capacity.jwt_macaroons;

import com.github.ndytar.capacity.properties.CapacityJwtPropertie;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;

@Service
public class RefreshTokenService {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenService.class);
    private CapacityJwtPropertie jwtPropertie;

    public RefreshTokenService(CapacityJwtPropertie jwtPropertie) {
        this.jwtPropertie = jwtPropertie;

    }
    private SecretKey cleSignature() {
        byte[] cleBytes = Base64.getDecoder().decode(jwtPropertie.getKeysecret());
        return Keys.hmacShaKeyFor(cleBytes);
    }

    public String generer(String username, String uuid) {
        return Jwts.builder()
                .subject(username)
                .claim("type", "refresh")
                .claim("uuid",  uuid)       // uuid injecté
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + jwtPropertie.getRefduration()))
                .signWith(cleSignature())
                .compact();
    }

}
