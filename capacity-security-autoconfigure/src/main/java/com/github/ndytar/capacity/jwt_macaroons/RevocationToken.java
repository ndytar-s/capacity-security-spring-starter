package com.github.ndytar.capacity.jwt_macaroons;


import  com.github.ndytar.capacity.services.RevocationTokenService;
import  com.github.ndytar.capacity.services.TokenStorageService;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class RevocationToken implements RevocationTokenService {

    private final TokenStorageService tokenStorage;

    public RevocationToken(TokenStorageService tokenStorage) {
        this.tokenStorage = tokenStorage;
    }

    @Override
    public boolean revokeMacaroon(String jwtId, String macaroonId) {
            tokenStorage.deleteMacaroon(jwtId, macaroonId);
        return !tokenStorage.existsMacaroon(jwtId, macaroonId);
    }

    @Override
    public boolean revokeMacaroonsByJwt(String jwtId) {
        tokenStorage.deleteMacaroons(jwtId);
        return tokenStorage.findMacaroons(jwtId).isEmpty();
    }

    @Override
    public boolean revokeJwt(String jwtId) {
        log.info("Avant Revoke jwt {}", tokenStorage.existsJwt(jwtId));
        // Suppression des macaroons associés
        tokenStorage.deleteMacaroons(jwtId);
        // Suppression du JWT
        tokenStorage.deleteJwt(jwtId);
        log.info("Apres Revoke jwt {}", tokenStorage.existsJwt(jwtId));

        return !tokenStorage.existsJwt(jwtId);
    }
    @Override
    public boolean revokeAllJwt() {
        tokenStorage.deleteAllJwt();
        return true;
    }

    @Override
    public boolean revokeAllMacaroons() {
        tokenStorage.deleteAllMacaroons();
        return true;
    }
}
