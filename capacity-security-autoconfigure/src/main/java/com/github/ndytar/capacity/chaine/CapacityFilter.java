package com.github.ndytar.capacity.chaine;

import com.github.ndytar.capacity.auth.CapacityAuth;
import com.github.ndytar.capacity.jwt_macaroons.ExtractionToken;
import com.github.ndytar.capacity.jwt_macaroons.MacaroonService;
import com.github.ndytar.capacity.properties.CapacityJwtPropertie;
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
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class CapacityFilter extends OncePerRequestFilter {
    private final AuthenticationEntryPoint authenticationEntryPoint;
    private static final Logger log = LoggerFactory.getLogger(CapacityFilter.class);

private final ExtractionToken extractionToken;
    private final MacaroonService macaroonService;
    private final CapacityJwtPropertie jwtPropertie;
   SecurityAuditReporter auditReporter;
    private RequestMappingHandlerMapping handlerMapping;

    private  List<String> auditActions;
    private  String auditScop;
    private  String audiUsername;
    private  String audiPassword;

    public CapacityFilter(
            AuthenticationEntryPoint authenticationEntryPoint,
                          ExtractionToken extractionToken,
                          MacaroonService macaroonService,
                          SecurityAuditReporter auditReporter,
                          RequestMappingHandlerMapping handlerMapping,
                          CapacityJwtPropertie jwtPropertie) {
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.extractionToken = extractionToken;
        this.macaroonService = macaroonService;
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

            if (token != null && isJwt(token)) {
                log.info("Option Token");

                Claims claims = extractionToken.extractClaims(token);

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

                    // extraire uuid
                    String uuid = claims.get("uuid", String.class);

                    String deviceId = claims.get("deviceId", String.class);
                    audiUsername = deviceId;

                    log.info("JWT valide, scope : {}, actions : {}, uuid : {}",
                            scope, actions, uuid);

                    injecterAuth(token, scope, actions, oneTime, uuid);



                } else {
                    throw new BadCredentialsException("Token invalid or expired ");

                }


            } else {
                essayerMacaroon(token, request,response);
            }


            chain.doFilter(request, response);

        }
        catch (AuthenticationException  e){
            SecurityContextHolder.clearContext();

            authenticationEntryPoint.commence(
                    request,
                    response,
                    e
            );
        }
    }

private void essayerMacaroon(String token, HttpServletRequest request,HttpServletResponse response) throws ServletException, IOException {
    try {
        log.info("Option Macaroon");
        // si c'est un JWT, ne pas essayer comme Macaroon
        if (!isJwt(token ) && token != null) {


            Macaroon macaroon = macaroonService.deserialiser(token);

            // vérifier que c'est bien un Macaroon
            // en vérifiant que identifier n'est pas null
            if (macaroon.identifier == null) {
                throw new BadCredentialsException("Macaroon invalid");
            }


            String ressourceDemandee = request.getRequestURI();
            if (macaroonService.verifier(macaroon)) {
                log.warn("Macaroon invalid or expired");
                throw new BadCredentialsException("Macaroon invalid or expired");
            }
            String scope = extraireScopeMacaroon(macaroon);
            auditScop = scope;
            Set<String> actions = extraireActionsMacaroon(macaroon);
            auditActions = actions.stream().collect(Collectors.toList());
            boolean oneTime = extraireOneTimeMacaroon(macaroon);

            String uuid =  extractionToken.extractUuidMac(macaroon);
            //revoquer apres 1er usage
            if (oneTime) {
                macaroonService.revokeMacaroon(macaroon);
            }

            log.info("Macaroon valide, ressourceDemandee : {}, scopMacaroon:{} ", ressourceDemandee, scope);
            log.info("scope: {}, action: {}, oneTime: {}, uuid: {}", scope, actions, oneTime, uuid);
            injecterAuth(token, scope, actions, oneTime, uuid);
        }
    } catch (AuthenticationException ex) {

        SecurityContextHolder.clearContext();

        throw new BadCredentialsException("Macaroon invalid or expired");

    }
}

    // Nouvelle méthode extraction uuid Macaroon

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
                actions.add(c.substring("actions=".length()).toUpperCase());
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


    private void injecterAuth(String token, String scope,
                              Set<String> actions, boolean oneTime,
                               String uuid) {
        CapacityAuth auth = new CapacityAuth(
                token, scope, actions, oneTime, uuid);
        SecurityContext ctx = SecurityContextHolder.createEmptyContext();
        ctx.setAuthentication(auth);
        SecurityContextHolder.setContext(ctx);

    }
    private boolean isJwt(String token) {
        // un JWT a toujours 3 parties séparées par des points
       if (token != null && !token.isEmpty())
           return token.split("\\.").length == 3;
       return false;
    }
}