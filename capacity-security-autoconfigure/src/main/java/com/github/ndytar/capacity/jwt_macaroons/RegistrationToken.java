package com.github.ndytar.capacity.jwt_macaroons;

import  com.github.ndytar.capacity.services.RegistrationTokenService;
import  com.github.ndytar.capacity.services.TokenStorageService;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;

@Slf4j

public class RegistrationToken implements RegistrationTokenService {

    private final TokenStorageService tokenStorageService;

    public RegistrationToken(TokenStorageService tokenStorageService) {
        this.tokenStorageService = tokenStorageService;
    }

    @Override
    public void registerJwt(String jwtId, String deviceId, long ttlMs) {
        tokenStorageService.saveJwt(jwtId, deviceId, Duration.ofMillis(ttlMs));
    }
    @Override
    public void registerMacaroon(String jwtId, String macaroonId, long ttlMs) {
        tokenStorageService.saveMacaroon(jwtId, macaroonId, Duration.ofMillis(ttlMs));
    }

    @Override
    public boolean existsJwt(String jwtId) {
        return tokenStorageService.existsJwt(jwtId);
    }


    @Override
    public boolean existsMacaroon(
            String jwtId,
            String macaroonId) {


        return tokenStorageService.existsMacaroon(
                jwtId,
                macaroonId
        );
    }
}
