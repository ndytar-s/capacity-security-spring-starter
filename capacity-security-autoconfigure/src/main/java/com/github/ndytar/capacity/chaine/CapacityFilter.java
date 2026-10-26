package com.github.ndytar.capacity.chaine;


import com.github.ndytar.capacity.auth.CapacityAuth;
import com.github.ndytar.capacity.auth.Deduiction;
import com.github.ndytar.capacity.customclaims.CustomClaims;
import com.github.ndytar.capacity.customclaims.CustomClaimsService;
import com.github.ndytar.capacity.exception.RedisUnavailableException;
import com.github.ndytar.capacity.jwt_macaroons.ExtractionToken;
import com.github.ndytar.capacity.jwt_macaroons.JwtService;
import com.github.ndytar.capacity.jwt_macaroons.MacaroonService;
import com.github.ndytar.capacity.proof.dPop.DpopProof;
import com.github.ndytar.capacity.proof.dPop.DpopService;
import com.github.ndytar.capacity.properties.CapacityDpopPropertie;
import com.github.ndytar.capacity.properties.CapacityJwtPropertie;
import com.github.ndytar.capacity.properties.CapacityMacaoonPropertie;
import com.github.nitram509.jmacaroons.Macaroon;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;
/**
 * MODIFICATIONS PAR RAPPORT À L'ORIGINAL :
 * - Ajout de AGENT_PATH_PATTERN et de la détection de route.
 * - Nouvelle branche : si la route matche /agent/**, on construit une LISTE
 *   de CapacityAuth (une par capacité envoyée) et on la stocke en attribut
 *   de requête, au lieu d'injecter une seule Authentication dans le
 *   SecurityContextHolder.
 * - Le flux existant (JWT/macaroon unique, injecterAuth, SecurityContextHolder)
 *   reste strictement inchangé pour toute route qui n'est pas /agent/**.
 * - La révocation one-time n'est plus faite ici pour la voie agent : elle
 *   est déplacée dans CapacityDecision.resoudre(...), au moment où la
 *   capacité choisie sert réellement. Le flux classique garde son
 *   comportement actuel (non modifié) pour éviter toute régression ;
 *   à corriger séparément si vous voulez aligner les deux voies plus tard.
 */
@Component
public class CapacityFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(CapacityFilter.class);
    private static final String AGENT_PATH_PATTERN = "/agent/**";
    public static final String ATTR_CAPACITY_LIST = "PRECOMPUTED_CAPACITY_LIST";

    private final AntPathMatcher antPathMatcher = new AntPathMatcher();

    private final AuthenticationEntryPoint authenticationEntryPoint;
    private final ExtractionToken extractionToken;
    private final MacaroonService macaroonService;
    private final CapacityJwtPropertie jwtPropertie;
    private final CapacityMacaoonPropertie macaoonPropertie;
    private final HandlerExceptionResolver resolver;
    private final JwtService jwtService;
    private final CustomClaimsService customClaimes;
    private final Deduiction deduiction;
    private final DpopService dpopService;
    private final CapacityDpopPropertie isDop;


    public CapacityFilter(
            AuthenticationEntryPoint authenticationEntryPoint,
                          ExtractionToken extractionToken,
                          MacaroonService macaroonService,
                          CapacityMacaoonPropertie macaoonPropertie,
                          RequestMappingHandlerMapping handlerMapping,
                          CapacityJwtPropertie jwtPropertie,
                          @Qualifier("handlerExceptionResolver")
                          HandlerExceptionResolver resolver,
                          JwtService jwtService,
                          CustomClaimsService customClaimes,
                          Deduiction deduiction,
                          DpopService dpopService,
                          CapacityDpopPropertie isDop) {
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.extractionToken = extractionToken;
        this.macaroonService = macaroonService;
        this.macaoonPropertie = macaoonPropertie;
        this.jwtPropertie = jwtPropertie;
        this.resolver = resolver;
        this.jwtService = jwtService;
        this.customClaimes = customClaimes;
        // handlerMapping conservé pour parité avec l'original (non utilisé
        // directement ici, comme dans votre code existant)
        this.deduiction = deduiction;

        this.dpopService = dpopService;
        this.isDop = isDop;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        try {
            boolean isAgentRoute = antPathMatcher.match(AGENT_PATH_PATTERN, request.getRequestURI());

            if (isAgentRoute) {
                List<CapacityAuth> liste = construireListeCapacites(request);
                request.setAttribute(ATTR_CAPACITY_LIST, liste);
            } else {

                traiterRequeteClassique(request);
            }


        } catch (AuthenticationException e) {
            SecurityContextHolder.clearContext();
            authenticationEntryPoint.commence(request, response, e);
            return;
        } catch (RedisUnavailableException ex) {
            SecurityContextHolder.clearContext();
            log.warn(ex.getMessage());
            resolver.resolveException(request, response, null,
                    new RedisUnavailableException("Redis is unavailable", ex));
            return;
        } catch (org.apache.tomcat.websocket.AuthenticationException e) {
            throw new BadCredentialsException("Token invalid or expired/revoked ");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        chain.doFilter(request, response);
    }

    /**
     * FLUX CLASSIQUE — copie exacte du comportement d'origine, non modifiée.
     */
    private void traiterRequeteClassique(HttpServletRequest request) throws Exception {
        String token = request.getHeader(jwtPropertie.getHeadername());

        if (token != null && isJwt(token)) {

            isRedise(token);
            Claims claims = extractionToken.extractClaims(token);

            if (claims != null) {
                verifyCustomClaims(claims);

                String scope = claims.get("scope", String.class);

                List<String> actionsList = claims.get("actions", List.class);

                Long subjectId =  claims.get("subject_id", Long.class);

                boolean personnel = claims.get("personnel", Boolean.class);

                String jkt = claims.get("jkt", String.class);

               if (isDop.isActive())
                   proved(jkt,token,request);

               Set<String> actions = actionsList != null
                        ? new HashSet<>(actionsList)
                        : Set.of("READ");

                boolean oneTime = Boolean.TRUE.equals(claims.get("one_time", Boolean.class));

                String uuid = claims.get("uuid", String.class);

                injecterAuth(token,subjectId, personnel, scope, actions, oneTime, jkt, uuid);

            } else {
                throw new BadCredentialsException("Token invalid or expired ");
            }
        } else {
            /***
             *  Poove avec macaroon non encore verifier
             */
            essayerMacaroon(token, request);
        }
    }

    /**
     * VOIE AGENTIC — nouvelle méthode. Boucle sur chaque token envoyé,
     * réutilise l'extraction JWT/macaroon existante, construit la liste.
     * Ne révoque pas les one-time ici (voir CapacityDecision).
     * *C'est une liste CapacityAuth
     */
    private List<CapacityAuth> construireListeCapacites(HttpServletRequest request) throws Exception {

        List<String> tokens = Collections.list(request.getHeaders(jwtPropertie.getHeadername())).stream()
                .flatMap(valeur -> Arrays.stream(valeur.split(",")))
                .map(String::trim)
                .filter(t -> !t.isEmpty())
                .toList();
        if (tokens.isEmpty()) {
            throw new BadCredentialsException("No capacity provided");
        }
        List<CapacityAuth> liste = new ArrayList<>();
       boolean prouve = false;
        for (String token : tokens) {

            if (token == null || token.isBlank()) continue;

            if (isJwt(token)) {

                isRedise(token);
                Claims claims = extractionToken.extractClaims(token);
                if (claims == null) throw new BadCredentialsException("Token invalid or expired");
                verifyCustomClaims(claims);

                String scope = claims.get("scope", String.class);

                List<String> actionsList = claims.get("actions", List.class);

                Set<String> actions = actionsList != null ? new HashSet<>(actionsList) : Set.of("READ");

                boolean oneTime = Boolean.TRUE.equals(claims.get("one_time", Boolean.class));

                String uuid = claims.get("uuid", String.class);

                String jkt = claims.get("jkt", String.class);

               if (!prouve && isDop.isActive()){
                   prouve = true;// Pouver une seul fois le premier token
                   proved(jkt,token,request);
               }

                Long subjectId = claims.get("subject_id", Long.class);
                boolean personnel = claims.get("personnel", Boolean.class);

                liste.add(new CapacityAuth(token, scope, actions, oneTime, subjectId,jkt,personnel, uuid));
            } else {
                Macaroon macaroon = macaroonService.deserialiser(token);
                verifyCustomCaveat(macaroon);
                if (macaroon.identifier == null) throw new BadCredentialsException("Macaroon invalid");
                if (macaroonService.verifier(macaroon)) throw new BadCredentialsException("Token invalid or expired");

                String scope = ExtractionToken.extraireScopeMacaroon(macaroon,deduiction);
                Set<String> actions = ExtractionToken.extraireActionsMacaroon(macaroon);
                boolean oneTime = ExtractionToken.extraireOneTimeMacaroon(macaroon);
                String uuid = extractionToken.extractUuidMac(macaroon);
                String jkt = "";// a definir
                Long subjectId = Long.parseLong(extractionToken.extractIdSubjectInMac(macaroon));
                boolean personnel = extractionToken.persennelInMac(macaroon);

                liste.add(new CapacityAuth(token, scope, actions, oneTime, subjectId,jkt,personnel, uuid));

            }
        }

        if (liste.isEmpty()) throw new BadCredentialsException("No capacity provided");
        return liste;
    }

    // ==== Méthodes ci-dessous : reprises telles quelles de l'original ====

    private void essayerMacaroon(String token, HttpServletRequest request) throws Exception {
        if (token != null && !isJwt(token)) {
            Macaroon macaroon = macaroonService.deserialiser(token);
            verifyCustomCaveat(macaroon);

            if (macaroon.identifier == null) {
                throw new BadCredentialsException("Macaroon invalid");
            }

            if (macaroonService.verifier(macaroon)) {
                log.warn("Token invalid or expired");
                throw new BadCredentialsException("Token invalid or expired");
            }
            String scope = ExtractionToken.extraireScopeMacaroon(macaroon,deduiction);

            Set<String> actions = ExtractionToken.extraireActionsMacaroon(macaroon);

            boolean oneTime = ExtractionToken.extraireOneTimeMacaroon(macaroon);

            String subjectId = extractionToken.extractIdSubjectInMac(macaroon);

            Long subjectIdVal = subjectId != null ? Long.parseLong(subjectId) : null;

            boolean personnel = extractionToken.persennelInMac(macaroon);

            String uuid = extractionToken.extractUuidMac(macaroon);

            String jkt = "";
            if (oneTime) {
                macaroonService.revokeMacaroon(macaroonService.serialiser(macaroon));
            }
            injecterAuth(token,subjectIdVal,personnel, scope, actions, oneTime, jkt, uuid);
        }
    }


    private void injecterAuth(String token, Long subjectId, boolean personnel, String scope, Set<String> actions, boolean oneTime, String jwt, String uuid) {

        CapacityAuth auth = new CapacityAuth(token, scope, actions, oneTime,subjectId, jwt, personnel, uuid);
        log.info("-----------CapacityAuth ----------- : {} ,{} ,{} ,{}, {}", auth.getResourceScope(),auth.getSujectId(),auth.isPersonnel(),auth.getActions(), auth.getJkt());

        SecurityContext ctx = SecurityContextHolder.createEmptyContext();
        ctx.setAuthentication(auth);
        SecurityContextHolder.setContext(ctx);
    }

    private boolean isJwt(String token) {
        if (token != null && !token.isEmpty())
            return token.split("\\.").length == 3;
        return false;
    }

    private void isRedise(String token) throws org.apache.tomcat.websocket.AuthenticationException {
        if (macaoonPropertie.isRedis()) {
            jwtService.isJwtRedis(token);
        }
    }

    void verifyCustomClaims(Claims claims) throws Exception {
        Map<String, Object> rawClaims = claims.get("customClaims", Map.class);
        if (rawClaims != null) {
            Map<String, String> mapClaims = rawClaims.entrySet().stream()
                    .collect(Collectors.toMap(Map.Entry::getKey, e -> String.valueOf(e.getValue())));
            if (!customClaimes.verify(new CustomClaims(mapClaims)))
                throw new BadCredentialsException("Invalid Token");
        }
    }

    void verifyCustomCaveat(Macaroon macaroon) throws Exception {
        String rawClaims = ExtractionToken.extraireCustomCaveatMacaroon(macaroon);
        Map<String, String> customClaims = null;
        if (rawClaims != null) customClaims = parseCustomClaims(rawClaims);
        if (!customClaimes.verify(new CustomClaims(customClaims)))
            throw new BadCredentialsException("Invalid Token");
    }

    private Map<String, String> parseCustomClaims(String rawClaims) {
        if (rawClaims == null || rawClaims.isBlank()) return Map.of();
        String content = rawClaims.replaceFirst("^\\{", "").replaceFirst("\\}$", "");
        if (content.isBlank()) return Map.of();
        return Arrays.stream(content.split(","))
                .map(entry -> entry.split("=", 2))
                .collect(Collectors.toMap(entry -> entry[0].trim(), entry -> entry[1].trim()));
    }
    private void proved(String jkt, String token, HttpServletRequest request) {
       DpopProof dpopProof = dpopService.extractDpopProof(request);

       if (!dpopService.verifyPayload(dpopProof,request,token) || !dpopService.verifySignature(dpopProof,jkt) ){
           throw new BadCredentialsException("Capacity not proved !");
       }
       else log.info("-------------------Proved !-------------");
    }
}


