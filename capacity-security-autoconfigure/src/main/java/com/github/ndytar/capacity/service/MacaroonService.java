package com.github.ndytar.capacity.service;

import com.github.ndytar.capacity.properties.CapacityProperties;
import com.github.nitram509.jmacaroons.Macaroon;
import com.github.nitram509.jmacaroons.MacaroonsBuilder;
import com.github.nitram509.jmacaroons.MacaroonsVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDate;
import java.util.UUID;

public class MacaroonService {

    private static final Logger log = LoggerFactory.getLogger(MacaroonService.class);


    private final CapacityProperties    properties;
    private final TokenRedisService     tokenRedisService;
    private final boolean redisEnabled;
    public MacaroonService(CapacityProperties properties,
                           TokenRedisService tokenRedisServices) {
        this.properties       = properties;
        this.tokenRedisService = tokenRedisServices;
        redisEnabled = properties.getRedis().isEnabled();
    }

    public Macaroon creer(String ressource) {

        String id       = UUID.randomUUID().toString();
        String location = properties.getMacaroon().getLocation();
        String cleSecrete   = secretActif();


        long dureeMs = properties.getJwt().getDuree();

        Macaroon macaroon = MacaroonsBuilder.create(location, cleSecrete, id);
        log.info("UUID: {}", id);
        MacaroonsBuilder builder = new MacaroonsBuilder(macaroon);
        builder.add_first_party_caveat("ressource=" + ressource);

        Macaroon result = builder.getMacaroon();

        // stocker dans Redis si activé
        if (redisEnabled) {
            tokenRedisService.stockerMacaroon(id, ressource, dureeMs);
            log.info("Macaroon stocké dans Redis : {}", id);
        }

        log.info("Macaroon créé pour : {}", ressource);
        return result;
    }
    // clé Macaroon séparée ou clé JWT si non définie
    private String secretActif() {
        String secretMacaroon = properties.getMacaroon().getSecret();
        return secretMacaroon != null ? secretMacaroon : properties.getJwt().getSecret();
    }
    public Macaroon attenuate(Macaroon macaroon, String... caveats) {
        MacaroonsBuilder builder = new MacaroonsBuilder(macaroon);

        for (String caveat : caveats) {
            builder.add_first_party_caveat(caveat.replace(" ", ""));
            log.info("Caveat ajouté : {}", caveat);
        }

        return builder.getMacaroon();
    }

    public boolean verifier(Macaroon macaroon, String ressourceDemandee) {
        boolean strict = properties.getRedis().isEnabled();
        // vérifier dans Redis si activé
        if (redisEnabled) {
            if (!tokenRedisService.existeMacaroon(macaroon.identifier)) {
                log.warn("Macaroon révoqué ou absent de Redis : {}", macaroon.identifier);
                return false;
            }
        }

        MacaroonsVerifier verifier = new MacaroonsVerifier(macaroon);

        verifier.satisfyGeneral(caveat -> {
            String c = caveat.replace(" ", "");

            if (c.startsWith("expire=")) {
                String dateStr       = c.substring("expire=".length());
                LocalDate expiration = LocalDate.parse(dateStr);
                return !LocalDate.now().isAfter(expiration);
            }

            if (c.startsWith("ressource=")) {
                String ressource = c.substring("ressource=".length());
                return ressource.equals(ressourceDemandee);
            }

            // caveat inconnu : selon config strict
            return !strict;
        });

        boolean valide = verifier.isValid(secretActif());
        log.info("Macaroon valide : {}", valide);
        return valide;
    }

    public String serialiser(Macaroon macaroon)    { return macaroon.serialize(); }
    public Macaroon deserialiser(String token)      { return MacaroonsBuilder.deserialize(token); }
}