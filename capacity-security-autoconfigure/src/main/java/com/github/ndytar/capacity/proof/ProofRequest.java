package com.github.ndytar.capacity.proof;

import java.util.Map;

public record ProofRequest(
        String resource,
        Map<String, String> elements
) {
    public String get(String key) {
        return elements.get(key);
    }

    public boolean has(String key) {
        return elements.containsKey(key);
    }
}
