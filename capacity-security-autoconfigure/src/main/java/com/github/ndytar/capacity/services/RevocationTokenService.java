package com.github.ndytar.capacity.services;

public interface RevocationTokenService {

    boolean revokeMacaroon(String jwtId, String macaroonId);

    boolean revokeMacaroonsByJwt(String jwtId);

    boolean revokeJwt(String jwtId);

    boolean revokeAllJwt();

    boolean revokeAllMacaroons();
}