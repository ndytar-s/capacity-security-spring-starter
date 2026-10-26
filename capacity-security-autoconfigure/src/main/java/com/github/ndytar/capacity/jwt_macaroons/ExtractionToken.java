package com.github.ndytar.capacity.jwt_macaroons;

import com.github.ndytar.capacity.auth.Deduiction;
import com.github.ndytar.capacity.exception.InvalidTokenException;
import com.github.ndytar.capacity.properties.CapacityJwtPropertie;
import com.github.ndytar.capacity.services.ExtractionTokenService;
import com.github.nitram509.jmacaroons.CaveatPacket;
import com.github.nitram509.jmacaroons.Macaroon;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;


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
            System.out.println(">>> APPEL extract Claims in jwt <<<");
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
    public String extractjkt(String jwt) {

        Claims claims = extractClaims(jwt);

        if (claims == null) {
            return null;
        }
        return claims.get("jkt", String.class);
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

    @Override
    public String extractIdSubject(String jwt) {
        Claims claims = extractClaims(jwt);
        if (claims == null) {
            return null;
        }
        return claims.get("subject_id", String.class);
    }

    @Override
    public boolean perseneel(String jwt) {
        Claims claims = extractClaims(jwt);
        if (claims == null) {
            return false;
        }
        return Boolean.parseBoolean(claims.get("personnel", String.class));
    }

    @Override
    public String extractIdSubjectInMac(Macaroon macaroon) {
        for (CaveatPacket caveat : macaroon.caveatPackets) {
            String c = caveat.getValueAsText().replace(" ", "");
            if (c.startsWith("subjectId=")) {
                return c.substring("subjectId=".length());
            }
        }
        return null;
    }

    @Override
    public boolean persennelInMac(Macaroon macaroon) {
        for (CaveatPacket caveat : macaroon.caveatPackets) {
            if (caveat.getValueAsText().replace(" ", "").equals("personnel=true")) {
                return true;
            }
        }
        return false;
    }

    public static  String extraireCustomCaveatMacaroon(Macaroon macaroon) {
        for (CaveatPacket caveat : macaroon.caveatPackets) {
            String c = caveat.getValueAsText().replace(" ", "");
            if (c.startsWith("customClaims=")) {
                return c.substring("customClaims=".length());
            }
        }
        return null;
    }

    public static Set<String> extraireActionsMacaroon(Macaroon macaroon) {
        Set<String> effectives = null;               // null = aucune contrainte vue
        for (CaveatPacket caveat : macaroon.caveatPackets) {
            String c = caveat.getValueAsText().replace(" ", "");
            if (!c.startsWith("actions=")) continue;
            Set<String> contrainte = Arrays.stream(c.substring("actions=".length()).split(","))
                    .map(String::toUpperCase).collect(Collectors.toSet());
            System.out.println("Action in macaroon : " + contrainte);
            if (effectives == null || effectives.contains("*")) effectives = new HashSet<>(contrainte);
            else if (!contrainte.contains("*")) effectives.retainAll(contrainte);
        }
        return effectives == null ? Set.of("READ") : effectives;   // défaut seulement s'il n'y a aucun caveat
    }

    public static boolean extraireOneTimeMacaroon(Macaroon macaroon) {
        for (CaveatPacket caveat : macaroon.caveatPackets) {
            if (caveat.getValueAsText().replace(" ", "").equals("oneTime=true")) {
                return true;
            }
        }
        return false;
    }


    public static String extraireScopeMacaroon(Macaroon m, Deduiction deduiction) {
        String courant = null;
        for (CaveatPacket caveat : m.caveatPackets) {
            String c = caveat.getValueAsText().replace(" ", "");
            if (!c.startsWith("ressource=")) continue;
            String r = c.substring("ressource=".length());
            System.out.println("Resource in macaronn"+r);
            if (courant == null) courant = r;
            else if (deduiction.scopeCouvre(courant, r, r)) courant = r;          // plus étroit : il devient effectif
            else if (!deduiction.scopeCouvre(r, courant, courant))                // ni plus étroit ni plus large
                throw new BadCredentialsException("Ressource hors du périmètre du macaroon");
            // sinon r est plus large que courant : sans effet
        }
        return courant == null ? "/**" : courant;
    }
}