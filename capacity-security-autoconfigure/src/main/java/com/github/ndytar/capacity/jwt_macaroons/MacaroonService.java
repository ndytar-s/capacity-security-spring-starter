 package com.github.ndytar.capacity.jwt_macaroons;

 import com.github.ndytar.capacity.exception.InvalidTokenException;
 import com.github.ndytar.capacity.properties.CapacityJwtPropertie;
 import com.github.ndytar.capacity.properties.CapacityMacaoonPropertie;
 import com.github.ndytar.capacity.services.RegistrationTokenService;
 import com.github.nitram509.jmacaroons.*;
 import io.jsonwebtoken.Claims;
 import org.slf4j.Logger;
 import org.slf4j.LoggerFactory;
 import org.springframework.stereotype.Service;

 import java.time.Duration;
 import java.time.Instant;
 import java.util.HashSet;
 import java.util.List;
 import java.util.Set;
 import java.util.UUID;
 import java.util.concurrent.atomic.AtomicBoolean;

 @Service
public class MacaroonService {
     private final CapacityJwtPropertie jwtPropertie;
     private final CapacityMacaoonPropertie macaoonPropertie;
     private final ExtractionToken extractionToken;
     private final RevocationToken revocationToken;
     private final RegistrationTokenService registrationToken;
    private static final Logger log = LoggerFactory.getLogger(MacaroonService.class);


    public MacaroonService(
            CapacityMacaoonPropertie macaoonPropertie,
            CapacityJwtPropertie jwtPropertie,
            ExtractionToken extractionToken,
            RevocationToken revocationToken,
            RegistrationTokenService registrationToken) {


        this.macaoonPropertie = macaoonPropertie;
        this.jwtPropertie = jwtPropertie;
        this.extractionToken = extractionToken;
        this.revocationToken = revocationToken;
        this.registrationToken = registrationToken;
    }
    public String creer(String jwtToken, String ressource, Set<String> actions, boolean oneTime) {

        String jwtId = extractionToken.extractJwtId(jwtToken);
        if (macaoonPropertie.isRedis())
            if (jwtId == null ||  !registrationToken.existsJwt(jwtId))
                return null;

        String idMac = UUID.randomUUID().toString();

        Macaroon macaroon = MacaroonsBuilder.create(
            macaoonPropertie.getLocation(), macaoonPropertie.getKeySecret(), idMac);


        if (jwtToken == null || jwtToken.isBlank())
            throw ApiExceptions.jwtAbsent();


        Claims claims = extractionToken.extractClaims(jwtToken);
        if (claims == null)
            throw ApiExceptions.jwtInvalide();


        String scope = claims.get("scope", String.class);
        log.debug("Scope du JWT: {}", scope);

            if(!scope.matches(ressource
                .replace("/**", "(/.*)?")
                .replace("/*",  "/[^/]*")
                .replace("{id}", "[^/]*"))) {
                throw ApiExceptions.ressourceInterdite(ressource);
            }

        if (actions == null || actions.isEmpty())
            throw ApiExceptions.parametreInvalide("Au moins une action doit être demandée");


        MacaroonsBuilder builder = new MacaroonsBuilder(macaroon);
        builder.add_first_party_caveat("ressource=" + ressource);

                // extraire actions
        List<String> actionsList = claims.get("actions", List.class);
        log.info("actionsList: {}", actionsList);
        Set<String> actionsRquise = actionsList != null ? new HashSet<>(actionsList) : Set.of("READ");

        for (String action : actions) {
                if (!actionsRquise.contains(action.toUpperCase()))
                    throw ApiExceptions.actionInterdite(action);
            builder.add_first_party_caveat("actions=" + action.toUpperCase());

        }

     if(oneTime){
         builder.add_first_party_caveat("oneTime=true");
     }

        String jwtd = extractionToken.extractJwtId(jwtToken);
        if (jwtd != null) {
            log.info("jwtd with create mac: {}", jwtd);
            builder.add_first_party_caveat("uuid=" + jwtd+":"+idMac);
        }
    Macaroon result = builder.getMacaroon();
       log.info("extract uuid mac in creet mac {}",extractionToken.extractUuidMac(result));
        if (macaoonPropertie.isRedis()) {
            registrationToken.registerMacaroon(jwtd, idMac, jwtPropertie.getDuration());
        }

    return serialiser(result);
}


     public String attenuate(String token, String... caveats) {

        if (token == null || token.isBlank())
            return null;

        Macaroon macaroon = deserialiser(token);

         if (verifier(macaroon))
            return null;

         String uuidParent = extractionToken.extractUuidMac(macaroon);
         if(uuidParent == null)
             throw ApiExceptions.parametreInvalide("Macaroon sans uuid");

         String[] ids = uuidParent.split(":");

         String uuidJwt = ids[0];
         MacaroonsBuilder builder = new MacaroonsBuilder(macaroon);

         for(String caveat : caveats){
             String normalized = caveat.replace(" ","");

             if(normalized.startsWith("expire=")){
                 Duration duration = Duration.parse(normalized.substring("expire=".length()));
                 builder.add_first_party_caveat("expire=" + Instant.now().plus(duration));
             }else{
                 builder.add_first_party_caveat(normalized);
             }
         }


         Macaroon temporaire = builder.getMacaroon();
         String uuidMac = UUID.randomUUID().toString();
         Macaroon result = reconstruireSansUuidParent(temporaire, uuidJwt, uuidMac);
         if(macaoonPropertie.isRedis()){
             registrationToken.registerMacaroon(uuidJwt, uuidMac, jwtPropertie.getDuration());
         }

         return serialiser(result);
     }
     private Macaroon reconstruireSansUuidParent(Macaroon parent, String uuidJwt, String uuidMac) {

         MacaroonsBuilder builder = MacaroonsBuilder.modify(MacaroonsBuilder.create(
                         parent.location,
                         macaoonPropertie.getKeySecret(),
                         parent.identifier
                 ));


         for (CaveatPacket caveat :
                 parent.caveatPackets) {
             String value = caveat.getValueAsText().replace(" ", "");
             /*
              * On ignore l'ancien identifiant
              */
             if (value.startsWith("uuid=")) {
                 continue;
             }
             builder.add_first_party_caveat(value);
         }

         /*
          * Nouvelle identité
          */
         builder.add_first_party_caveat("uuid=" + uuidJwt + ":" + uuidMac);

         return builder.getMacaroon();
     }

//Attention! le retoure de cette methode est inversé
  public boolean verifier(Macaroon macaroon) {
        try {


            AtomicBoolean isValid = new AtomicBoolean(true);

          String uuid = extractionToken.extractUuidMac(macaroon);

          if (uuid == null) {
              return true;
          }
          String[] ids = uuid.split(":");
          if(ids.length != 2) {
              return true;
          }

          if (macaoonPropertie.isRedis()) {
              boolean existe = registrationToken.existsMacaroon(ids[0], ids[1]);
              if(!existe){
                  return true;
              }
          }

            MacaroonsVerifier verifier = new MacaroonsVerifier(macaroon);
            verifier.satisfyGeneral(caveat -> {
                String c = caveat.replace(" ", "");
                if (c.startsWith("expire=")) {
                    log.warn("TimeMacaroon: {},  TimeIstant: {}", c.substring("expire=".length()),Instant.now());
                    Instant expiry = Instant.parse(c.substring("expire=".length()));
                    log.warn("lastedTime : {}", !Instant.now().isAfter(expiry));
                    isValid.set(!Instant.now().isAfter(expiry));
                    return !Instant.now().isAfter(expiry);
                }
                // ressource, action, ip, one_time
                // satisfaits ici car vérifiés dans CapacityAuthManager
                if (c.startsWith("ressource=")) return true;
                if (c.startsWith("actions="))    return true;
                if (c.startsWith("oneTime=true")) return true;
                if (c.startsWith("uuid")) return true;
                return !macaoonPropertie.isStric();
            });
          boolean valide = verifier.isValid(macaoonPropertie.getKeySecret());
          isValid.set(valide && isValid.get());
          return !isValid.get();
        }
        catch ( MacaroonValidationException e) {
            throw new InvalidTokenException("Invalid token signature", e);
        }
    }

     public boolean revokeMacaroon(Macaroon macaroon) {
         String jwtId = extractionToken.extractJwtId(macaroon);
         String macaroonId = extractionToken.extractMacaroonId(macaroon);

         if (jwtId == null || macaroonId == null)
             return false;

         return revocationToken.revokeMacaroon(jwtId, macaroonId);
     }
     public boolean revokeMacaroonsByJwt(String jwt) {

         String jwtId = extractionToken.extractJwtId(jwt);
         if (jwtId == null ||  !registrationToken.existsJwt(jwtId))
             return false;

         return revocationToken.revokeMacaroonsByJwt(jwtId);
     }


     public boolean revokeAllMacaroons() {
         return revocationToken.revokeAllMacaroons();
     }

    public String serialiser(Macaroon macaroon)    { return macaroon.serialize(); }
    public Macaroon deserialiser(String token) {
        try {
            if (token != null)
                return MacaroonsBuilder.deserialize(token);
            return null;
         }
        catch ( Exception e) {
         throw new InvalidTokenException("Invalid token signature", e);
        }
    }



 }