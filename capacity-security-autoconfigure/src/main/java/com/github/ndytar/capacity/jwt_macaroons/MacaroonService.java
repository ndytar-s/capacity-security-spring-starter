 package com.github.ndytar.capacity.jwt_macaroons;

 import com.github.ndytar.capacity.properties.CapacityJwtPropertie;
 import com.github.ndytar.capacity.properties.CapacityMacaoonPropertie;
 import com.github.ndytar.capacity.register.TokenRedisService;
 import com.github.nitram509.jmacaroons.Macaroon;
 import com.github.nitram509.jmacaroons.MacaroonsBuilder;
 import com.github.nitram509.jmacaroons.MacaroonsVerifier;
 import io.jsonwebtoken.Claims;
 import java.time.LocalDate;
 import java.util.HashSet;
 import java.util.List;
 import java.util.Set;
 import java.util.UUID;


public class MacaroonService {



    private TokenRedisService tokenRedisService;
    private JwtService jwtService;
     private  UuidService uuidService;
     private CapacityMacaoonPropertie macaoonPropertie;
     private CapacityJwtPropertie jwtPropertie;

    public MacaroonService(UuidService uuidService, JwtService jwtService, TokenRedisService tokenRedisService,
                           CapacityMacaoonPropertie macaoonPropertie,
                           CapacityJwtPropertie jwtPropertie) {
        this.uuidService = uuidService;
        this.jwtService = jwtService;
        this.tokenRedisService = tokenRedisService;
        this.macaoonPropertie = macaoonPropertie;
        this.jwtPropertie = jwtPropertie;
    }

    /**
     * @param jwtToken
     * @param ressource
     * @param actions
     * @param oneTime

     * @return
     * Creer = Attenuer une capacité sous form d'un macaroon
     */
    public Macaroon creer(String jwtToken, String ressource, Set<String> actions, boolean oneTime) {
    String idMac = UUID.randomUUID().toString();

    Macaroon macaroon = MacaroonsBuilder.create(
            macaoonPropertie.getLocation(), macaoonPropertie.getKeySecret(), idMac);


        if (jwtToken == null || jwtToken.isBlank())
            throw ApiExceptions.jwtAbsent();


        Claims claims = jwtService.extraireSiValide(jwtToken);
        if (claims == null)
            throw ApiExceptions.jwtInvalide();


        String scope = claims.get("scope", String.class);

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
        Set<String> actionsRquise = actionsList != null ? new HashSet<>(actionsList) : Set.of("READ");

        for (String action : actions) {

                if (!actionsRquise.contains(action))
                    throw ApiExceptions.actionInterdite(action);


            builder.add_first_party_caveat("actions=" + action);

        }

     if(oneTime){
         builder.add_first_party_caveat("oneTime=true");
     }

        // extraire uuid depuis JWT et injecter dans Macaroon
        String uuid = claims.get("uuid", String.class);
        if (uuid != null) {
            builder.add_first_party_caveat("uuid=" + idMac+":"+uuid);
        }
    Macaroon result = builder.getMacaroon();

    if (macaoonPropertie.isRedis()) {
        String deviceId = tokenRedisService.extractDeviceJwt(jwtToken);
        tokenRedisService.stocker("macaroon",uuid+":"+idMac,deviceId, jwtPropertie.getDuration());
    }

    return result;
}


    public Macaroon attenuate(Macaroon macaroon, String... caveats) {
    MacaroonsBuilder builder = new MacaroonsBuilder(macaroon);
    for (String caveat : caveats) {
        builder.add_first_party_caveat(caveat.replace(" ", ""));
    }

    return builder.getMacaroon();
    }

    public boolean revokerMac(Macaroon macaroon){
        if (macaoonPropertie.isRedis())
           return tokenRedisService.deleteMacaoon(macaroon);
        else
            return false;
    }
    public boolean revokerMacWithToken(String token){
        if (macaoonPropertie.isRedis())
            return   tokenRedisService.deleteAllMacaroonsWithJwt(token);
        return false;
    }


  public boolean verifier(Macaroon macaroon) {

        if (macaoonPropertie.isRedis()) {
            if (!tokenRedisService.isMacaroon(macaroon)) {
                return false;
            }
        }

        MacaroonsVerifier verifier = new MacaroonsVerifier(macaroon);
        verifier.satisfyGeneral(caveat -> {
            String c = caveat.replace(" ", "");
            if (c.startsWith("expire=")) {
                LocalDate expiration = LocalDate.parse(
                        c.substring("expire=".length()));
                return !LocalDate.now().isAfter(expiration);
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

      return valide;
    }

    public String serialiser(Macaroon macaroon)    { return macaroon.serialize(); }
    public Macaroon deserialiser(String token)      { return MacaroonsBuilder.deserialize(token); }
}