package com.github.ndytar.capacity.services;
import java.time.Duration;
import java.util.Set;

public interface TokenStorageService {


    void saveJwt(String jwtId, String deviceId, Duration ttl);
    void saveMacaroon(String jwtId, String macaroonId, Duration ttl);
    boolean existsJwt(String jwtId);
    boolean existsMacaroon(String jwtId, String macaroonId);
    Set<String> findMacaroons(String jwtId);
    void deleteJwt(String jwtId);
    void deleteMacaroon(String jwtId, String macaroonId);
    void deleteMacaroons(String jwtId);
    void deleteAllJwt();
    void deleteAllMacaroons();

}
