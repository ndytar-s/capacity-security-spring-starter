package com.github.ndytar.capacity.filter;

import com.github.ndytar.capacity.auth.CapacityAuth;
import com.github.ndytar.capacity.service.JwtService;
import com.github.ndytar.capacity.service.MacaroonService;
import com.github.nitram509.jmacaroons.Macaroon;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


public class CapacityFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(CapacityFilter.class);

    private String HEADER;

    public void setHEADER(String HEADER) {
        this.HEADER = HEADER;
    }

    private final JwtService jwtService;

    private final MacaroonService macaroonService;
    // constructeur pour l'auto-configuration
    public CapacityFilter(JwtService jwtService, MacaroonService macaroonService) {
        this.jwtService      = jwtService;
        this.macaroonService = macaroonService;
    }
    @Override
    protected void doFilterInternal(
            HttpServletRequest  request,
            HttpServletResponse response,
            FilterChain         chain
    ) throws ServletException, IOException {

        try {
            String token = request.getHeader(HEADER);

            if (token != null) {
                Claims claims = jwtService.extraireSiValide(token);
                if (claims!=null) {

                    String ressource = claims.get("ressource", String.class);

                    log.info("JWT valide, ressource : {}", ressource);

                    injecterAuth(token, ressource);

                } else {
                    // essayer Macaroon
                    essayerMacaroon(token, request);
                }

            } else {
                log.warn("Aucun token dans la requête");
            }

            chain.doFilter(request, response);

        } finally {
            SecurityContextHolder.clearContext();
        }
    }
    private void essayerMacaroon(String token, HttpServletRequest request) {
        try {
            Macaroon macaroon        = macaroonService.deserialiser(token);
            String   ressourceDemandee = request.getRequestURI();

            if (macaroonService.verifier(macaroon, ressourceDemandee)) {
                log.info("Macaroon valide, ressource : {}", ressourceDemandee);
                injecterAuth(token, ressourceDemandee);
            } else {
                log.warn("Macaroon invalide ou caveat non satisfait");
            }

        } catch (Exception e) {
            log.warn("Token non reconnu : {}", e.getMessage());
        }
    }

    private void injecterAuth(String token, String ressource) {
        CapacityAuth auth    = new CapacityAuth(token, ressource);
        SecurityContext ctx  = SecurityContextHolder.createEmptyContext();
        ctx.setAuthentication(auth);
        SecurityContextHolder.setContext(ctx);
    }
}