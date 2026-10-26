package com.github.ndytar.capacity.customclaims;

import java.util.Map;

public record CustomClaims(Map<String, String> claims) {

    public CustomClaims {
        claims = Map.copyOf(claims);
    }
}