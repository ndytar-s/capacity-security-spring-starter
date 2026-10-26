 package com.github.ndytar.capacity.jwt_macaroons;

 import com.github.ndytar.capacity.auth.Deduiction;
 import com.github.ndytar.capacity.exception.ApiExceptions;
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
 import java.time.format.DateTimeParseException;
 import java.util.*;
 import java.util.concurrent.atomic.AtomicBoolean;
 import java.util.stream.Collectors;


public class MacaroonService {
     private final CapacityJwtPropertie jwtPropertie;
     private final CapacityMacaoonPropertie macaoonPropertie;
     private final ExtractionToken extractionToken;
     private final RevocationToken revocationToken;
     private final RegistrationTokenService registrationToken;
     private final Deduiction deduiction;
    private static final Logger log = LoggerFactory.getLogger(MacaroonService.class);


    public MacaroonService(
            CapacityMacaoonPropertie macaoonPropertie,
                           CapacityJwtPropertie jwtPropertie,
            ExtractionToken extractionToken, RevocationToken revocationToken,
            RegistrationTokenService registrationToken, Deduiction deduiction) {


        this.macaoonPropertie = macaoonPropertie;
        this.jwtPropertie = jwtPropertie;
        this.extractionToken = extractionToken;
        this.revocationToken = revocationToken;
        this.registrationToken = registrationToken;
        this.deduiction = deduiction;
    }
    public String creer(String jwtToken, String ressource, Set<String> actions, boolean oneTime) {
        if (jwtToken == null || jwtToken.isBlank())
            throw ApiExceptions.jwtAbsent();
        String jwtId = extractionToken.extractJwtId(jwtToken);
        if (macaoonPropertie.isRedis())
            if (jwtId == null ||  !registrationToken.existsJwt(jwtId))
                return null;

        String idMac = UUID.randomUUID().toString();

        Macaroon macaroon = MacaroonsBuilder.create(
            macaoonPropertie.getLocation(), macaoonPropertie.getKeySecret(), idMac);

        Claims claims = extractionToken.extractClaims(jwtToken);
        if (claims == null)
            throw ApiExceptions.jwtInvalide();


        // Extraction et verification de scope(token) et resource demandee
        MacaroonsBuilder builder = new MacaroonsBuilder(macaroon);
        String scope = claims.get("scope", String.class);
        if (scope == null) throw ApiExceptions.jwtInvalide();

        String ressourceEffective = (ressource == null || ressource.isBlank()) ? scope : ressource;
         log.info("scopetoken : {}, source: {}", scope, ressourceEffective);
        if (!ressourceEffective.trim().equals(scope)
                && !deduiction.scopeCouvre(scope, ressourceEffective, ressourceEffective)) {
            throw ApiExceptions.ressourceInterdite(ressourceEffective);
        }

        builder.add_first_party_caveat("ressource=" + ressourceEffective);   // un seul caveat

        Long subjectId = claims.get("subject_id", Long.class);
        boolean personnel = claims.get("personnel", Boolean.class);

        if (subjectId != null)
            builder.add_first_party_caveat("subjectId=" + subjectId);
        if (personnel)
            builder.add_first_party_caveat("personnel=true");

        // eviter null actions
        if (actions == null || actions.isEmpty())
            throw ApiExceptions.parametreInvalide("At least one action must be requested");
        // extraire actions
        List<String> actionsList = claims.get("actions", List.class);
        Set<String> actionsRquise = actionsList != null ? new HashSet<>(actionsList) : Set.of("READ");
        //Lever exception si le token ne renferme pas action(s) demandee(s) et et ne contient pas un joker
        Set<String> demandees = actions.stream().map(String::toUpperCase)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        for (String action : demandees) {
            if (!actionsRquise.contains(action) && !actionsRquise.contains("*"))
                throw ApiExceptions.actionInterdite(action);
        }
        builder.add_first_party_caveat("actions=" + String.join(",", demandees));

     if(oneTime)
         builder.add_first_party_caveat("oneTime=true");

        Map<String, String>   customClaims = getCustomClaims(claims);

        if (customClaims!= null)
            builder.add_first_party_caveat("customClaims=" + customClaims);

        String jwtd = extractionToken.extractJwtId(jwtToken);
        if (jwtd != null)
            builder.add_first_party_caveat("uuid=" + jwtd+":"+idMac);

    Macaroon result = builder.getMacaroon();
       log.info("extract uuid mac in creet mac {}",extractionToken.extractUuidMac(result));
        if (macaoonPropertie.isRedis()) {
            registrationToken.registerMacaroon(jwtd, idMac, jwtPropertie.getDuration());
        }

    return serialiser(result);
}


     public String attenuate(String token, String... caveats) {

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
             }
             else if (normalized.startsWith("actions=")) {
                 Set<String> detenues = ExtractionToken.extraireActionsMacaroon(macaroon);
                 Set<String> demandees = Arrays.stream(normalized.substring("actions=".length()).split(","))
                         .map(String::toUpperCase).collect(Collectors.toCollection(LinkedHashSet::new));
                 if (!detenues.contains("*") && !detenues.containsAll(demandees))
                     throw ApiExceptions.actionInterdite(String.join(",", demandees));
                 builder.add_first_party_caveat("actions=" + String.join(",", demandees));
             }

             else if (normalized.startsWith("ressource=")) {
                 String nouvelle = normalized.substring("ressource=".length());
                 String actuelle = ExtractionToken.extraireScopeMacaroon(macaroon, deduiction);
                 if (!deduiction.scopeCouvre(actuelle, nouvelle, nouvelle))
                     throw ApiExceptions.parametreInvalide("Ressource non couverte par le macaroon : " + nouvelle);
                 builder.add_first_party_caveat("ressource=" + nouvelle);
             }

             else if (normalized.startsWith("personnel=")) {
                 String personnel = normalized.substring("personnel=".length());
                     builder.add_first_party_caveat("personnel=" + personnel);

             }

             else if (normalized.startsWith("subjectId=")) {
                 String subjectId = normalized.substring("subjectId=".length());
                     builder.add_first_party_caveat("subjectId="+subjectId);
             }

             else if (normalized.startsWith("customClaims=")) {
                 String customClaims = normalized.substring("customClaims=".length());
                     builder.add_first_party_caveat("customClaims="+customClaims);
             }

             else if (normalized.startsWith("oneTime=")) {
                 String oneTime = normalized.substring("oneTime=".length());
                     builder.add_first_party_caveat("oneTime="+oneTime);
             }
                 builder.add_first_party_caveat(normalized);

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

        if (macaroon == null)
            throw new InvalidTokenException("INVALID_TOKEN,"," Null token not acceptable",null);

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
              // 1. Il est préférable de trimmer plutôt que de supprimer tous les espaces
              // car les JSON de customClaims ont besoin de leurs caractères, ou utilisez .startsWith() prudemment.
              String c = caveat.trim().replace(" ", "");

              if (c.startsWith("expire=")) {
                  String timeString = c.substring("expire=".length());
                  log.warn("TimeMacaroon extrait: {}, TimeInstant actuel: {}", timeString, Instant.now());

                  try {
                      Instant expiry;
                      // Si c'est une durée relative (ex: PT10M) au lieu d'une date absolue
                      if (timeString.startsWith("PT") || timeString.startsWith("P")) {
                          expiry = Instant.now().plus(Duration.parse(timeString));
                      } else {
                          expiry = Instant.parse(timeString);
                      }

                      boolean nonExprire = !Instant.now().isAfter(expiry);
                      isValid.set(nonExprire);
                      return nonExprire;

                  } catch (DateTimeParseException e) {
                      log.error("Échec de parsing du caveat d'expiration '{}'. Erreur: {}", timeString, e.getMessage());
                      isValid.set(false);
                      return false; // Invalide le caveat si le format est corrompu
                  }
              }

              // ressource, action, ip, one_time
              // satisfaits ici car vérifiés dans CapacityAuthManager
              if (c.startsWith("ressource=")) return true;
              if (c.startsWith("personnel=true")) return true;
              if (c.startsWith("subjectId=")) return true;
              if (c.startsWith("actions="))    return true;
              if (c.startsWith("oneTime=true")) return true;
              if (c.startsWith("uuid")) return true;
              if (c.startsWith("customClaims")) return true;

              return !macaoonPropertie.isStric();
          });

          boolean valide = verifier.isValid(macaoonPropertie.getKeySecret());
          isValid.set(valide && isValid.get());
          return !isValid.get();
        }
        catch ( MacaroonValidationException e) {
            throw new InvalidTokenException("INVALID_SIGNATURE","Invalid token signature", e);
        }
    }

     public boolean revokeMacaroon(String mac) {
         Macaroon macaroon = deserialiser(mac);
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

    public String serialiser(Macaroon macaroon)    {
        if (macaroon == null )
            throw new InvalidTokenException("INVALID_TOKEN,"," Null token not acceptable",null);
        return macaroon.serialize();
    }
    public Macaroon deserialiser(String token) {
        try {
            if (token == null || token.isBlank())
                throw new InvalidTokenException("INVALID_TOKEN,"," Null token not acceptable",null);
            return MacaroonsBuilder.deserialize(token);

         }
        catch ( Exception e) {
         throw new InvalidTokenException("INVALID_SIGNATURE,","Invalid token signature", e);
        }
    }

     Map<String, String> getCustomClaims(Claims claims) {
         Map<String, Object> rawClaims = claims.get("customClaims", Map.class);
         if (rawClaims != null) {
             return rawClaims.entrySet()
                     .stream()
                     .collect(Collectors.toMap(Map.Entry::getKey, e -> String.valueOf(e.getValue())
                     ));
         }
         return null;

     }
 }