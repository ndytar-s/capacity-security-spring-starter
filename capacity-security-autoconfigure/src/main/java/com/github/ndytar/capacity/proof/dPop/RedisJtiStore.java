package com.github.ndytar.capacity.proof.dPop;

import com.github.ndytar.capacity.exception.RedisUnavailableException;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;

public class RedisJtiStore implements JtiStore {
    private final StringRedisTemplate redis;

    public RedisJtiStore(StringRedisTemplate redis) { this.redis = redis; }


    @Override
    public boolean tryRegister(String jti, Duration ttl) {
        try {
            return Boolean.TRUE.equals(
                    redis.opsForValue().setIfAbsent("dpop:jti:" + jti, "1", ttl));
        } catch (RedisConnectionFailureException e) {
            throw new RedisUnavailableException("Redis is unavailable", e);
        }
    }
}