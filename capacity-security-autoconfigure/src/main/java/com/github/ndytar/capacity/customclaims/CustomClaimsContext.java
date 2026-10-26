package com.github.ndytar.capacity.customclaims;

import java.util.HashMap;
import java.util.Map;

public class CustomClaimsContext {

    private final Map<String, String> claims = new HashMap<>();

    public void put(String key, String value) {
        claims.put(key, value);
    }

    public String get(String key) {
        return claims.get(key);
    }

    public Map<String, String> claims() {
        return Map.copyOf(claims);
    }
}