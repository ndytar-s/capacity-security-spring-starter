package com.github.ndytar.capacity.jwt_macaroons;

import org.springframework.stereotype.Component;

@Component
public final class RedisKeys {

    private static final String JWT = "jwt:";
    private static final String MACAROON = "macaroon:";
    private static final String MACAROONS = "macaroons:";
    private static final String ALL_MACAROONS = "macaroons:all";

    private RedisKeys() {
    }

    public static String jwt(String jwtId) {
        return JWT + jwtId;
    }

    public static String macaroon(String jwtId, String macaroonId) {
        return MACAROON + jwtId + ":" + macaroonId;
    }

    public static String macaroons(String jwtId) {
        return MACAROONS + jwtId;
    }

    public static String allMacaroons() {
        return ALL_MACAROONS;
    }
    public String jwtPattern() {
        return JWT + "*";
    }
    public String macaroonsPattern() {
        return MACAROON + "*";
    }
}
