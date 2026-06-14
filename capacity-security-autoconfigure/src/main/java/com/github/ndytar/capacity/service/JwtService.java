package com.github.ndytar.capacity.service;

import com.github.ndytar.capacity.properties.CapacityProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;


import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;


public class JwtService {
    private final TokenRedisService tokenRedisService;
    private final CapacityProperties properties;

    // constructeur au lieu de @Autowired
    public JwtService(TokenRedisService tokenRedisService,
                      CapacityProperties properties) {
        this.tokenRedisService = tokenRedisService;
        this.properties        = properties;
    }




    private SecretKey cleSignature() {
        String cleSecrete = properties.getJwt().getSecret();
        byte[] cleBytes = Base64.getDecoder().decode(cleSecrete);
        return Keys.hmacShaKeyFor(cleBytes);
    }

    // 1. GÉNÉRER un token JWT pour une ressource
    public String generer(String ressource) {
        long DUREE_MS = properties.getJwt().getDuree();
        String token = Jwts.builder()
                .claim("ressource", ressource)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + DUREE_MS))
                .signWith(cleSignature())
                .compact();

        tokenRedisService.stocker(token, ressource, DUREE_MS);
        return token;
    }

    // 2. EXTRAIRE le payload
    public Claims extraire(String token) {
        return Jwts.parser()
                .verifyWith(cleSignature())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // 3. VÉRIFIER si valide
    // estValide retourne le payload si valide, null sinon
    public Claims extraireSiValide(String token) {
        try {
            Claims claims = extraire(token);

            // vérifier dans Redis
            if (!tokenRedisService.existe(token)) {
                return null;
            }

            return claims;  // payload utilisé directement

        } catch (JwtException e) {
            return null;
        }
    }
}