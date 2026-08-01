package com.github.ndytar.capacity.register;

import com.github.ndytar.capacity.properties.CapacityJwtPropertie;
import com.github.nitram509.jmacaroons.CaveatPacket;
import com.github.nitram509.jmacaroons.Macaroon;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

public class TokenRedisService {

    private StringRedisTemplate redisTemplate;
    private CapacityJwtPropertie jwtPropertie;
    public TokenRedisService(StringRedisTemplate redisTemplate,
                             CapacityJwtPropertie jwtPropertie) {
        this.redisTemplate = redisTemplate;
        this.jwtPropertie = jwtPropertie;

    }

    private SecretKey cleSignature() {
        byte[] cleBytes = Base64.getDecoder().decode(jwtPropertie.getKeysecret());
        return Keys.hmacShaKeyFor(cleBytes);
    }
    private static final Logger log = LoggerFactory.getLogger(TokenRedisService.class);



    private static final String PREFIX_JWT      = "jwt:";
    private static final String PREFIX_MACAROON = "macaroon:";


    public void stocker(String prefix, String uuid, String deviceId, long dureeMs) {

        if(PREFIX_MACAROON.equals(prefix)) {

            String newMacaroon = PREFIX_MACAROON+uuid;// ic uuid inclu inMac
            
            String cletoken = PREFIX_JWT + uuid;
            String cleSet = PREFIX_MACAROON + uuid;
            redisTemplate.opsForSet().add(cleSet, newMacaroon);
            log.info("macaroon stoke uuidmac : {}",uuid);
            
            Long timTokenMs = redisTemplate.getExpire(cletoken, TimeUnit.MILLISECONDS);
            if(timTokenMs != null && timTokenMs > 0 ) {
                redisTemplate.expire(cleSet, Duration.ofMillis(timTokenMs));
            }else {
                redisTemplate.delete(cleSet);
            }
            
        }else {
            redisTemplate.opsForValue().set(
                    PREFIX_JWT + uuid,
                    deviceId,
                    dureeMs,
                    TimeUnit.MILLISECONDS);
            log.info("UUID de jwt stocké uuid: {} username {} deviceId {}", uuid, deviceId);
        }
    }
    // récupérer username depuis redis; a voire si on accepe un token a la place de uuid de user
    public Optional<String> getUsernameJwt(String prefix, String uuid) {
        String valeur = redisTemplate.opsForValue().get(prefix + uuid);
        if (valeur == null) return Optional.empty();
        return Optional.of(valeur.split(":")[0]);
    }
    // vérifier uuid
    public boolean existe(String prefix, String uuid) {
        if (uuid == null) return false;
        return Boolean.TRUE.equals(redisTemplate.hasKey(prefix + uuid));
    }

    /**
     * @param uuid
     * @return
     * Chaque macaroon a un uuid a lui et uuid de token generateur ce qui donne uuid = prefix:uuidMacaroon:uuidToken
     */

    /**
     * Supprimer le uuid de mararoon de Set Redis
     */
    public boolean deleteMacaoon(Macaroon macaroon){
        String uuidMac =extraireUuidMac(macaroon);

       String[] parties =  uuidMac.split(":");
       if(parties.length < 3) {
           throw new IllegalArgumentException("Illegal format of macaroon");
       }
       String idToken = parties[1];
       String cleSet = PREFIX_MACAROON + idToken;
       redisTemplate.opsForSet().remove(cleSet, uuidMac);
       return redisTemplate.delete(uuidMac);
    }
    public boolean isMacaroon(Macaroon macaroon){
        /**
         * Verifier son existance dans le Set et dans Value
         */
        String  uuidmaco = extraireUuidMac(macaroon);
        String uuid = redisTemplate.opsForSet().randomMember(uuidmaco);// recuper la valeur
        if (!redisTemplate.hasKey(uuid))
            return false;
        return  !redisTemplate.opsForSet().isMember( extraireUuidMac(macaroon)).isEmpty();
    }

    public boolean deleteAllMacaroonsWithJwt(String token) {
         String idtoken = extractUuidJwt(token);
         String cleSet = PREFIX_MACAROON + idtoken;
         Set<String> allMac = redisTemplate.opsForSet().members(cleSet);
         if(allMac != null && !allMac.isEmpty()){
             redisTemplate.delete(allMac);
         }
         return redisTemplate.delete(cleSet);
    }
    public boolean deleteJwt(String token) {
        if (token == null) return false;
       String uuidToken = extractUuidJwt(token);
        deleteAllMacaroonsWithJwt(uuidToken);
        return redisTemplate.delete(uuidToken);
    }
    public boolean deleteAllJwt(Set<String> tokens) {
        tokens.forEach(token -> deleteJwt(token));
        return true;
    }
    public String extractUuidJwt(String jwt ){
       Claims claims = extractClaims(jwt);
       if(claims==null) return null;
       String uuid = claims.get("uuid",  String.class);

       if (!redisTemplate.hasKey(uuid))
            return null;
       return uuid;
    }
    public String extractDeviceJwt(String jwt ){
        Claims claims = extractClaims(jwt);
        if(claims==null) return null;
        String deviceId = claims.get("deviceId",  String.class);
        return deviceId;
    }
    private Claims extractClaims(String jwt){
        return  Jwts.parser()
                .verifyWith(cleSignature())
                .build()
                .parseSignedClaims(jwt)
                .getPayload();
    }
    private String extraireUuidMac(Macaroon macaroon) {
        if (macaroon == null) return null;
        for (CaveatPacket caveat : macaroon.caveatPackets) {
            String c = caveat.getValueAsText().replace(" ", "");
            if (c.startsWith("uuid="))
                return c.substring("uuid=".length());
        }
        return null;
    }
}