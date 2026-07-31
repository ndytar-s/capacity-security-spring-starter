package com.github.ndytar.capacity.chaine;

import com.github.ndytar.capacity.auth.CapacityAuth;
import com.github.ndytar.capacity.jwt_macaroons.JwtService;
import com.github.ndytar.capacity.jwt_macaroons.MacaroonService;
import com.github.ndytar.capacity.properties.CapacityJwtPropertie;
import com.github.ndytar.capacity.register.TokenRedisService;
import com.github.ndytar.capacity.services.SecurityAuditReporter;
import com.github.nitram509.jmacaroons.CaveatPacket;
import com.github.nitram509.jmacaroons.Macaroon;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Component
public class CapacityFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(CapacityFilter.class);
   // @Value("${capacity.header.name}")
   // private String HEADER;


    private JwtService jwtService;
    private MacaroonService macaroonService;
    private TokenRedisService tokenRedisService;
    private CapacityJwtPropertie jwtPropertie;
   SecurityAuditReporter auditReporter;
    private RequestMappingHandlerMapping handlerMapping;

    private  List<String> auditActions;
    private  String auditScop;
    private  String audiUsername;
    private  String audiPassword;

    public CapacityFilter(JwtService jwtService,
                          MacaroonService macaroonService,
                          TokenRedisService tokenRedisService,
                          SecurityAuditReporter auditReporter,
                          RequestMappingHandlerMapping handlerMapping,
                          CapacityJwtPropertie jwtPropertie) {
        this.jwtService = jwtService;
        this.macaroonService = macaroonService;
        this.tokenRedisService = tokenRedisService;
        this.auditReporter = auditReporter;
        this.handlerMapping = handlerMapping;
        this.jwtPropertie = jwtPropertie;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest  request,
            HttpServletResponse response,
            FilterChain         chain
    ) throws ServletException, IOException {

        try {
            String token = request.getHeader(jwtPropertie.getHeadername());

            if (token != null) {
                Claims claims = jwtService.extraireSiValide(token);

                if (claims != null) {
                    // extraire scope
                 String  scope = claims.get("scope", String.class);
                  auditScop = scope;
                    // extraire actions
                    List<String>  actionsList = claims.get("actions", List.class);
                    auditActions = actionsList;
                    Set<String>  actions = actionsList != null
                            ? new HashSet<>(actionsList)
                            : Set.of("READ");

                    // extraire oneTime
                    boolean oneTime = Boolean.TRUE.equals(
                            claims.get("one_time", Boolean.class));

                    // extraire allowedIp
                    String allowedIp = claims.get("allowed_ip", String.class);

                    String uuid = claims.get("uuid", String.class);

                    String deviceId = claims.get("deviceId", String.class);
                    audiUsername = deviceId;

                    log.info("JWT valide, scope : {}, actions : {}, uuid : {}",
                            scope, actions, uuid);

                    injecterAuth(token, scope, actions, oneTime, allowedIp, uuid);



                } else {
                    // essayer Macaroon
                    essayerMacaroon(token, request);
                }

            } else {
                    log.warn("JWT non valide");
            }

            chain.doFilter(request, response);

        } finally {
            SecurityContextHolder.clearContext();
        }
    }

private void essayerMacaroon(String token, HttpServletRequest request) {
    try {
        // si c'est un JWT, ne pas essayer comme Macaroon
        if (isJwt(token)) {
            log.warn("JWT révoqué ou expiré, accès refusé");
            return;
        }
        Macaroon  macaroon = macaroonService.deserialiser(token);

        // vérifier que c'est bien un Macaroon
        // en vérifiant que identifier n'est pas null
        if (macaroon.identifier == null) {

        log.warn("Macaroon invalide");
        return;
        }


        String ressourceDemandee = request.getRequestURI();
        if (macaroonService.verifier(macaroon)) {
            String      scope     = extraireScopeMacaroon(macaroon);
            auditScop =  scope;
            Set<String> actions = extraireActionsMacaroon(macaroon);
            auditActions = (List<String>) actions;
            boolean oneTime = extraireOneTimeMacaroon(macaroon);
            String allowedIp = extraireallowedIp(macaroon);

            String uuid = extraireUuidMacaroon(macaroon);

            //revoquer apres 1er usage
            if (oneTime){
                macaroonService.revokerMac(macaroon);
            }


            log.info("Macaroon valide, ressourceDemandee : {}, scopMacaroon:{} ", ressourceDemandee, scope);
            injecterAuth(token, scope, actions, oneTime, allowedIp, uuid);
        } else {
            log.warn("Macaroon invalide");
        }
    } catch (IllegalArgumentException e) {
        log.warn("Token JWT révoqué ou invalide, pas un Macaroon");


    } catch (Exception e) {
        log.warn("Token non reconnu : {}", e.getMessage());
    }
}

    // Nouvelle méthode extraction uuid Macaroon
    private String extraireUuidMacaroon(Macaroon macaroon) {
        for (CaveatPacket caveat : macaroon.caveatPackets) {
            String c = caveat.getValueAsText().replace(" ", "");
            if (c.startsWith("uuid="))
                return c.substring("uuid=".length());
        }
        return null;
    }
    // extraire le scope depuis le caveat "ressource="
    private String extraireScopeMacaroon(Macaroon macaroon) {
        for (CaveatPacket caveat : macaroon.caveatPackets) {
            String c = caveat.getValueAsText().replace(" ", "");
            if (c.startsWith("ressource=")) {
                return c.substring("ressource=".length());
            }
        }
        return "/**";
    }
    private Set<String> extraireActionsMacaroon(Macaroon macaroon) {
        Set<String> actions = new HashSet<>();

        for (CaveatPacket caveat : macaroon.caveatPackets) {
            String c = caveat.getValueAsText().replace(" ", "");
            if (c.startsWith("actions=")) {
                actions.add(c.substring("actions=".length()));
            }
        }

        // par défaut READ si aucune action dans les caveats
        if (actions.isEmpty()) {
            actions.add("READ");
        }

        return actions;
    }
    private boolean extraireOneTimeMacaroon(Macaroon macaroon) {
        for (CaveatPacket caveat : macaroon.caveatPackets) {
            if(caveat.getValueAsText().replace(" ", "").equals("oneTime=true")) {
                return true;
            }
        }
        return false;
    }
    private String extraireallowedIp(Macaroon macaroon) {
        for (CaveatPacket caveat : macaroon.caveatPackets) {
            String c = caveat.getValueAsText().replace(" ", "");
            if (c.startsWith("allowedIp=")) {
                String ip = c.substring("allowedIp=".length());
                return ip.equals("null") ? null : ip;

            }
        }
        return null;
    }

    private void injecterAuth(String token, String scope,
                              Set<String> actions, boolean oneTime,
                              String allowedIp, String uuid) {
        CapacityAuth auth = new CapacityAuth(
                token, scope, actions, oneTime, allowedIp, uuid);
        SecurityContext ctx = SecurityContextHolder.createEmptyContext();
        ctx.setAuthentication(auth);
        SecurityContextHolder.setContext(ctx);

    }
    private boolean isJwt(String token) {
        // un JWT a toujours 3 parties séparées par des points
        return token.split("\\.").length == 3;
    }
}