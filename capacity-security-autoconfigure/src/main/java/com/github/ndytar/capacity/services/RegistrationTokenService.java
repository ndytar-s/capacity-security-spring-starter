package com.github.ndytar.capacity.services;

public interface RegistrationTokenService {

    void registerJwt(String jwtId, String deviceId, long ttlMs);

    void registerMacaroon(String jwtId, String macaroonId, long ttlMs);

    boolean existsJwt(String jwtId);

    boolean existsMacaroon(String jwtId, String macaroonId);
}
