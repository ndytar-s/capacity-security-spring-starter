package com.github.ndytar.capacity.jwt_macaroons;

import com.github.ndytar.capacity.exception.RedisUnavailableException;
import com.github.ndytar.capacity.services.TokenStorageService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.RedisConnectionFailureException;
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
        try {
            redisTemplate.opsForValue().set(RedisKeys.jwt(jwtId), deviceId, ttl);
        }
        catch (RedisConnectionFailureException e) {
            throw new RedisUnavailableException("Redis is unavailable", e);
        }
    }

    @Override
    public void saveMacaroon(String jwtId, String macaroonId, Duration ttl) {
        try {
            String key = RedisKeys.macaroons(jwtId);
            redisTemplate.opsForSet().add(key, macaroonId);
            redisTemplate.expire(key, ttl);
        }
        catch (RedisConnectionFailureException e) {
            throw new RedisUnavailableException("Redis is unavailable", e);
        }
    }

    @Override
    public boolean existsJwt(String jwtId) {
        try {
            return Boolean.TRUE.equals(redisTemplate.hasKey(RedisKeys.jwt(jwtId)));
        }
        catch (RedisConnectionFailureException e) {
            throw new RedisUnavailableException("Redis is unavailable", e);
        }
    }

    @Override
    public boolean existsMacaroon(String jwtId, String macaroonId) {
        try {
            String key = RedisKeys.macaroons(jwtId);
            return Boolean.TRUE.equals(redisTemplate.opsForSet().isMember(key, macaroonId));
        }
        catch (RedisConnectionFailureException e) {
            throw new RedisUnavailableException("Redis is unavailable", e);
        }
    }

    @Override
    public Set<String> findMacaroons(String jwtId) {
        try {
            return redisTemplate.opsForSet().members(RedisKeys.macaroons(jwtId));
        }
        catch (RedisConnectionFailureException e) {
            throw new RedisUnavailableException("Redis is unavailable", e);
        }
    }

    @Override
    public void deleteJwt(String jwtId) {
        try {
            redisTemplate.delete(RedisKeys.jwt(jwtId));
        }
        catch (RedisConnectionFailureException e) {
            throw new RedisUnavailableException("Redis is unavailable", e);
        }
    }

    @Override
    public void deleteMacaroon(String jwtId, String macaroonId) {
        try {
            String key = RedisKeys.macaroons(jwtId);
            redisTemplate.opsForSet().remove(key, macaroonId);
        }
        catch (RedisConnectionFailureException e) {
            throw new RedisUnavailableException("Redis is unavailable", e);
        }

    }
    @Override
    public void deleteMacaroons(String jwtId) {
        try {
            redisTemplate.delete(RedisKeys.macaroons(jwtId));
        }
        catch (RedisConnectionFailureException e) {
            throw new RedisUnavailableException("Redis is unavailable", e);
        }
    }

    @Override
    public void deleteAllJwt() {
        try {
            Set<String> keys = redisTemplate.keys(redisKeys.jwtPattern());
            if(keys != null && !keys.isEmpty()) {
                redisTemplate.delete(keys);
            }
        }
        catch (RedisConnectionFailureException e) {
            throw new RedisUnavailableException("Redis is unavailable", e);
        }
    }

    @Override
    public void deleteAllMacaroons() {
        try {
            Set<String> keys = redisTemplate.keys(redisKeys.macaroonsPattern());

            if(keys != null && !keys.isEmpty()) {
                redisTemplate.delete(keys);
            }
        }
        catch (RedisConnectionFailureException e) {
            throw new RedisUnavailableException("Redis is unavailable", e);
        }
    }
}
