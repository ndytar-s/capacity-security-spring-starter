package com.github.ndytar.capacity.jwt_macaroons;

import com.github.ndytar.capacity.services.TokenStorageService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Set;

@Slf4j
@Service
public class RedisTokenStorage implements TokenStorageService {


    private final StringRedisTemplate redisTemplate;
    private final RedisKeys redisKeys;


    public RedisTokenStorage(StringRedisTemplate redisTemplate, RedisKeys redisKeys) {
        this.redisTemplate = redisTemplate;
        this.redisKeys = redisKeys;
    }


    @Override
    public void saveJwt(String jwtId, String deviceId, Duration ttl) {
        redisTemplate.opsForValue().set(RedisKeys.jwt(jwtId), deviceId, ttl);
    }

    @Override
    public void saveMacaroon(String jwtId, String macaroonId, Duration ttl) {

        String key = RedisKeys.macaroons(jwtId);
        redisTemplate.opsForSet().add(key, macaroonId);
        redisTemplate.expire(key, ttl);
    }

    @Override
    public boolean existsJwt(
            String jwtId) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(RedisKeys.jwt(jwtId)));
    }

    @Override
    public boolean existsMacaroon(String jwtId, String macaroonId) {
        String key = RedisKeys.macaroons(jwtId);
        return Boolean.TRUE.equals(redisTemplate.opsForSet().isMember(key, macaroonId));
    }

    @Override
    public Set<String> findMacaroons(String jwtId) {
        return redisTemplate.opsForSet().members(RedisKeys.macaroons(jwtId));
    }

    @Override
    public void deleteJwt(String jwtId) {
    redisTemplate.delete(RedisKeys.jwt(jwtId));

    }

    @Override
    public void deleteMacaroon(String jwtId, String macaroonId) {
        String key = RedisKeys.macaroons(jwtId);
        Long revoc =   redisTemplate.opsForSet().remove(key, macaroonId);
        log.info("deleted mac {} ", revoc);
    }
    @Override
    public void deleteMacaroons(String jwtId) {
        redisTemplate.delete(RedisKeys.macaroons(jwtId));
    }

    @Override
    public void deleteAllJwt() {
        Set<String> keys = redisTemplate.keys(redisKeys.jwtPattern());
        if(keys != null && !keys.isEmpty()) {
            redisTemplate.delete(keys);
        }
    }

    @Override
    public void deleteAllMacaroons() {
        Set<String> keys = redisTemplate.keys(redisKeys.macaroonsPattern());

        if(keys != null && !keys.isEmpty()) {
            redisTemplate.delete(keys);
        }
    }
}
