package com.github.ndytar.capacity.config;


import com.github.ndytar.capacity.proof.dPop.*;
import com.github.ndytar.capacity.properties.CapacityDpopPropertie;
import com.github.ndytar.capacity.properties.CapacityMacaoonPropertie;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;


@AutoConfiguration
public class DpopConfig {

    @Bean
    public JtiStore jtiStore(CapacityMacaoonPropertie macaroonProps,
                             ObjectProvider<StringRedisTemplate> redis) {
        if (macaroonProps.isRedis()) {
            StringRedisTemplate template = redis.getIfAvailable();
            if (template == null) {
                throw new IllegalStateException("Redis enabled but no StringRedisTemplate bean found");
            }
            return new RedisJtiStore(template);
        }
        return new NoOpJtiStore();
    }

    @Bean
    public DpopService dpopService(JtiStore store, CapacityDpopPropertie props) {
        Duration window = (store instanceof NoOpJtiStore)
                ? Duration.ofSeconds(30)
                : Duration.ofSeconds(60);
        return new DpopServiceImpl(store, window, props);
    }
}