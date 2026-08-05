package com.github.ndytar.capacity.jwt_macaroons;

import com.github.ndytar.capacity.properties.CapacityJwtPropertie;
import com.github.ndytar.capacity.properties.CapacityMacaoonPropertie;
import com.github.ndytar.capacity.register.TokenRedisService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
import java.util.Set;


public class JwtService {

    private TokenRedisService tokenRedisService;
    private UuidService uuidService;
    private CapacityJwtPropertie jwtPropertie;
    private CapacityMacaoonPropertie redisPropertie;

    //@Value("${capacity.jwt.secret}")
   // private String cleSecrete;

   // @Value("${capacity.jwt.duree:900000}")
   // private long DUREE_MS;

   // @Value("${capacity.redis.enabled:false}")
   // private boolean redisEnabled;

    public JwtService(TokenRedisService tokenRedisService,
                      UuidService uuidService,
                      CapacityJwtPropertie jwtPropertie,
                      CapacityMacaoonPropertie redisPropertie) {
        this.tokenRedisService = tokenRedisService;
        this.uuidService = uuidService;
        this.jwtPropertie = jwtPropertie;
        this.redisPropertie = redisPropertie;
    }
    private SecretKey cleSignature() {
        byte[] cleBytes = Base64.getDecoder().decode(jwtPropertie.getKeysecret());
        return Keys.hmacShaKeyFor(cleBytes);
    }
    public String generer(String scope, Set<String> actions,
                          boolean oneTime, String deviceId,
                          String uuid) {

        String token = Jwts.builder()
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

        return token;
    }

    public Claims extraire(String token) {
        return Jwts.parser()
                .verifyWith(cleSignature())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public Claims extraireSiValide(String token) {
        try {
            Claims claims = extraire(token);
            String uuid = claims.get("uuid", String.class);
            // verifier dans redis
            if (redisPropertie.isRedis())
                if (!tokenRedisService.existe("jwt:",uuid)) {

                    return null;
                }

            // one_time : révoquer après premier usage
            Boolean oneTime = claims.get("one_time", Boolean.class);
            if (Boolean.TRUE.equals(oneTime) && redisPropertie.isRedis()) {
                tokenRedisService.deleteJwt(token);
            }

            return claims;

        } catch (JwtException e) {
            return null;
        }
    }
    public boolean revoker(String token) {
        if (redisPropertie.isRedis())
            return   tokenRedisService.deleteJwt(token);
        return false;

    }
    public boolean revokeAll(Set<String> token) {
        if (redisPropertie.isRedis())
            return tokenRedisService.deleteAllJwt(token);
        return false;

    }
}