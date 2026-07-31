package com.github.ndytar.capacity.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "capacity.macaroon")
public class CapacityMacaoonPropertie {
    private String location= "http://localhost:8080";
    private  boolean stric = true;
    private boolean redis = false;
    private String keySecret;

    public String getKeySecret() {
        return keySecret;
    }

    public void setKeySecret(String keySecret) {
        this.keySecret = keySecret;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public boolean isStric() {
        return stric;
    }

    public void setStric(boolean stric) {
        this.stric = stric;
    }

    public boolean isRedis() {
        return redis;
    }

    public void setRedis(boolean redis) {
        this.redis = redis;
    }
}
