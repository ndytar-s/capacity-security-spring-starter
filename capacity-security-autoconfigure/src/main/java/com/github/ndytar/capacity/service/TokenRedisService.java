package com.github.ndytar.capacity.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;


import java.util.concurrent.TimeUnit;

public class TokenRedisService {

    private static final Logger log = LoggerFactory.getLogger(TokenRedisService.class);

    private final StringRedisTemplate redisTemplate;


    public TokenRedisService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    private static final String PREFIX_JWT      = "jwt:";
    private static final String PREFIX_MACAROON = "macaroon:";

    // JWT : stocker
    public void stocker(String token, String ressource, long dureeMs) {
        String cle = PREFIX_JWT + token;
        redisTemplate.opsForValue().set(cle, ressource, dureeMs, TimeUnit.MILLISECONDS);
        log.info("JWT stocké dans Redis : {}", ressource);
    }

    // JWT : vérifier
    public boolean existe(String token) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(PREFIX_JWT + token));
    }

    // JWT : révoquer
    public void revoquer(String token) {
        redisTemplate.delete(PREFIX_JWT + token);
        log.info("JWT révoqué");
    }

    // Macaroon : stocker l'identifiant racine
    public void stockerMacaroon(String macaroonId, String ressource, long dureeMs) {
        String cle = PREFIX_MACAROON + macaroonId;
        redisTemplate.opsForValue().set(cle, ressource, dureeMs, TimeUnit.MILLISECONDS);
        log.info("Macaroon stocké dans Redis : {}", macaroonId);
    }

    // Macaroon : vérifier
    public boolean existeMacaroon(String macaroonId) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(PREFIX_MACAROON + macaroonId));
    }

    // Macaroon : révoquer
    public void revoquerMacaroon(String macaroonId) {
        redisTemplate.delete(PREFIX_MACAROON + macaroonId);
        log.info("Macaroon révoqué : {}", macaroonId);
    }
}