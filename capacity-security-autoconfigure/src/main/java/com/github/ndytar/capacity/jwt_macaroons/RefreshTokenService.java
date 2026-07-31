package com.github.ndytar.capacity.jwt_macaroons;

import com.github.ndytar.capacity.properties.CapacityJwtPropertie;
import com.github.ndytar.capacity.properties.CapacityMacaoonPropertie;
import com.github.ndytar.capacity.register.TokenRedisService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;

@Service
public class RefreshTokenService {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenService.class);

    private StringRedisTemplate redisTemplate;
    private UuidService uuidService;
    private TokenRedisService tokenRedisService;
    private CapacityJwtPropertie jwtPropertie;
    private CapacityMacaoonPropertie macaoonPropertie;

 //   @Value("${capacity.jwt.secret}")
  //  private String cleSecrete;
    //@Value("${capacity.refresh.duree:604800000}")
   // private long duree;
  //  @Value("${capacity.refresh.redis-enabled:false}")
  //  private boolean redisEnabled;


    public RefreshTokenService(TokenRedisService tokenRedisService, UuidService uuidService,
                               StringRedisTemplate redisTemplate,
                               CapacityMacaoonPropertie macaoonPropertie, CapacityJwtPropertie jwtPropertie) {
        this.tokenRedisService = tokenRedisService;
        this.uuidService = uuidService;
        this.redisTemplate = redisTemplate;
        this.macaoonPropertie = macaoonPropertie;
        this.jwtPropertie = jwtPropertie;
    }

    private SecretKey cleSignature() {
        byte[] cleBytes = Base64.getDecoder().decode(jwtPropertie.getKeysecret());
        return Keys.hmacShaKeyFor(cleBytes);
    }

    /**
     * generer un refressh token sans scop ni les action
     * @param username
     * @param uuid
     * @return
     */
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

    /**
     * Valider token son existance dans Redis cas ou il est actif et verifier le tkoen en question s'il est valide
     * @param prefix
     * @param token
     * @return
     */
    public Optional<String> valider(String prefix, String token) {
        Claims claims = extraire(token);
        if (claims == null)
            return Optional.empty();

        String uuid = claims.get("uuid",String.class);

        if (macaoonPropertie.isRedis())
            if (!tokenRedisService.existe(prefix, uuid))
                 return Optional.empty();

        return validerJwt(claims);
    }

    public Claims extraire(String token) {
        try {
        return Jwts.parser()
                .verifyWith(cleSignature())
                .build()
                .parseSignedClaims(token)
                .getPayload();
        } catch (JwtException e) {
            log.warn("Refresh token JWT invalide : {}", e.getMessage());
            return null;
        }
    }


    private Optional<String> validerJwt(Claims claims) {
            if (!"refresh".equals(claims.get("type"))) {
                return Optional.empty();
            }

            return Optional.of(claims.getSubject());
    }


}
