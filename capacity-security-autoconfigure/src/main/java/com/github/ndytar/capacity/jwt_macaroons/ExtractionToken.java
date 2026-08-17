package com.github.ndytar.capacity.jwt_macaroons;

import com.github.nitram509.jmacaroons.CaveatPacket;
import com.github.nitram509.jmacaroons.Macaroon;
import  com.github.ndytar.capacity.exception.InvalidTokenException;
import  com.github.ndytar.capacity.properties.CapacityJwtPropertie;
import  com.github.ndytar.capacity.services.ExtractionTokenService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;

import javax.crypto.SecretKey;
import java.util.Base64;


public class ExtractionToken implements ExtractionTokenService {

    private final CapacityJwtPropertie jwtPropertie;

    public ExtractionToken(CapacityJwtPropertie jwtPropertie) {
        this.jwtPropertie = jwtPropertie;

    }

    private SecretKey cleSignature() {
        try {
            byte[] cleBytes = Base64.getDecoder()
                    .decode(jwtPropertie.getKeysecret());
            return Keys.hmacShaKeyFor(cleBytes);
        }
        catch (SignatureException e) {
            throw new InvalidTokenException("INVALID_SIGNATURE", "Invalid token signature", e);

        } catch (IllegalArgumentException e) {
        throw new IllegalStateException("Error: The configured token signing key is invalid", e);
    }

    }

    @Override
    public Claims extractClaims(String jwt) {
        try {
            if (jwt == null || jwt.isBlank()) {
                return null;
            }
            return Jwts.parser()
                    .verifyWith(cleSignature())
                    .build()
                    .parseSignedClaims(jwt)
                    .getPayload();
        } catch (SignatureException e) {
            throw new InvalidTokenException("INVALID_SIGNATURE", "Invalid token signature", e);

        }
        catch (JwtException e) {
            throw new InvalidTokenException("INVALID_TOKEN"," Invalid format token", e);
        }

    }


    @Override
    public String extractJwtId(String jwt) {
        Claims claims = extractClaims(jwt);
        if (claims == null) {
            return null;
        }
        return claims.get("uuid", String.class);
    }


    @Override
    public String extractDeviceId(String jwt) {

        Claims claims = extractClaims(jwt);

        if (claims == null) {
            return null;
        }

        return claims.get(
                "deviceId",
                String.class);
    }


    @Override
    public String extractUuidMac(Macaroon macaroon) {

        if (macaroon == null) {
            return null;
        }

        for (CaveatPacket caveat : macaroon.caveatPackets) {

            String value = caveat.getValueAsText().replace(" ", "");

            if (value.startsWith("uuid=")) {
                return value.substring("uuid=".length());
            }
        }

        return null;
    }


    @Override
    public String extractJwtId(Macaroon macaroon) {

        String uuidMac = extractUuidMac(macaroon);

        if (uuidMac == null) {
            return null;
        }
        String[] ids = uuidMac.split(":");

        if (ids.length != 2) {
            return null;
        }

        return ids[0];
    }

    @Override
    public String extractMacaroonId(Macaroon macaroon) {

        String uuidMac = extractUuidMac(macaroon);

        if (uuidMac == null) {
            return null;
        }
        String[] ids = uuidMac.split(":");

        if (ids.length != 2) {
            return null;
        }
        return ids[1];
    }

}