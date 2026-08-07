package com.github.ndytar.capacity.services;

import com.github.nitram509.jmacaroons.Macaroon;
import io.jsonwebtoken.Claims;

public interface ExtractionTokenService {

    Claims extractClaims(String jwt);

    String extractJwtId(String jwt);

    String extractDeviceId(String jwt);

    String extractUuidMac(Macaroon macaroon);

    String extractJwtId(Macaroon macaroon);

    String extractMacaroonId(Macaroon macaroon);


}
