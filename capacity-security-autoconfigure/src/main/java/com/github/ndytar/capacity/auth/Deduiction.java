package com.github.ndytar.capacity.auth;

import  com.github.ndytar.capacity.annotation.RequiresCapacity;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.method.HandlerMethod;

import java.util.Map;


public class Deduiction {
    Logger log = LoggerFactory.getLogger(Deduiction.class);

    private static final Map<String, String> HTTP_ACTION = Map.of(
            "GET",    "READ",
            "POST",   "WRITE",
            "PUT",    "WRITE",
            "DELETE", "DELETE",
            "PATCH",  "WRITE"
    );

    /**
     * Déduit le scope requis depuis le handler ou l'URI originale en cas d'erreur.
     */
    public String deduireScope(HandlerMethod handler, HttpServletRequest request) {

        // === CAS 1 : Forward d'erreur Spring (404, exception, etc.) ===
        // Quand une requête échoue, Spring fait un forward interne vers /error.
        // L'URI de la requête ORIGINALE est conservée dans cet attribut.
        String originalUri = (String) request.getAttribute(RequestDispatcher.ERROR_REQUEST_URI);
        if (originalUri != null) {
            String scope = extraireScopeDepuisUri(originalUri);
            log.info("Forward d'erreur détecté. URI originale={}, scope déduit={}", originalUri, scope);
            return scope;
        }

        // === CAS 2 : Requête normale ===
        RequestMapping classMapping = handler.getBeanType().getAnnotation(RequestMapping.class);
        if (classMapping != null && classMapping.value().length > 0) {
            String rawPath = classMapping.value()[0];

            // Protection si le placeholder n'a pas été résolu par Spring
            // (ex: ${server.error.path:${error.path:/error}})
            if (rawPath.contains("${")) {
                log.warn("Placeholder non résolu détecté: {}. Fallback sur URI courante.", rawPath);
                return extraireScopeDepuisUri(request.getRequestURI());
            }

            String scope = rawPath.endsWith("/**") ? rawPath : rawPath + "/**";
            log.info("Deduire scope {}", scope);
            return scope;
        }

        return "/**";
    }

    /**
     * Extrait le scope depuis une URI brute.
     * /audits/123     → /audits/**
     * /comptes        → /comptes/**
     */
    private String extraireScopeDepuisUri(String uri) {
        if (uri == null || uri.equals("/")) {
            return "/**";
        }
        // Ignore les query params
        String path = uri.split("\\?")[0];
        // Premier segment après le /
        int secondSlash = path.indexOf('/', 1);
        String base = (secondSlash > 0) ? path.substring(0, secondSlash) : path;
        return base + "/**";
    }

    // --- Le reste de votre classe reste inchangé ---

    public String deduireAction(HandlerMethod handler, HttpServletRequest request) {
        RequiresCapacity annotation = handler.getMethodAnnotation(RequiresCapacity.class);
        if (annotation != null && annotation.actions().length > 0) {
            return annotation.actions()[0];
        }
        return HTTP_ACTION.getOrDefault(request.getMethod(), "READ");
    }

    public boolean scopeCouvre(String scopeToken, String urlDemandee, String scopeRequis) {
        String patternToken = scopeToken
                .replace("/**", "(/.*)?")
                .replace("/*", "/[^/]*")
                .replace("{id}", "[^/]*");

        boolean urlDansToken = urlDemandee.matches(patternToken);
        boolean tokenCouvreRequis =
                scopeToken.equals(scopeRequis)
                        || scopeToken.equals("/**")
                        || scopeRequis.startsWith(scopeToken.replace("/**", ""));

        log.info("urlDansToken: {}, tokenCouvreRequis: {}", urlDansToken, tokenCouvreRequis);
        return urlDansToken && tokenCouvreRequis;
    }
}
