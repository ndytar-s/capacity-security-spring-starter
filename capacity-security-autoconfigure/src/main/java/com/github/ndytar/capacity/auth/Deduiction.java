package com.github.ndytar.capacity.auth;

import com.github.ndytar.capacity.annotation.RequiresCapacity;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.method.HandlerMethod;

import java.util.Map;


public class Deduiction {

    private static final Map<String, String> HTTP_ACTION = Map.of(
            "GET",    "READ",
            "POST",   "WRITE",
            "PUT",    "WRITE",
            "DELETE", "DELETE",
            "PATCH",  "WRITE"
    );

    public String deduireScope(HandlerMethod handler) {

        // déduire depuis @RequestMapping sur la classe
        RequestMapping classMapping = handler
                .getBeanType()
                .getAnnotation(RequestMapping.class);

        if (classMapping != null && classMapping.value().length > 0) {
            return classMapping.value()[0] + "/**";
        }

        return "/**";
    }

    // déduire l'action depuis @RequiresCapacity ou méthode HTTP
    public String deduireAction(HandlerMethod handler,
                                 HttpServletRequest request) {

        // priorité : @RequiresCapacity sur la méthode
        RequiresCapacity annotation = handler
                .getMethodAnnotation(RequiresCapacity.class);
        if (annotation != null && annotation.actions().length > 0) {
            return annotation.actions()[0];
        }

        // déduire depuis la méthode HTTP
        return HTTP_ACTION.getOrDefault(request.getMethod(), "READ");
    }
    // vérifier que le scope du token couvre le scope requis
    public boolean scopeCouvre(String scopeToken, String urlDemandee,
                                String scopeRequis) {

        // convertir scopeToken en pattern regex
        String patternToken = scopeToken
                .replace("/**", "(/.*)?")  // /comptes/** → /comptes(/.*)?
                .replace("/*",  "/[^/]*")
                .replace("{id}", "[^/]*");

        // 1. URL demandée correspond au scope du token
        boolean urlDansToken = urlDemandee.matches(patternToken);

        // 2. scope du token couvre le scope requis
        boolean tokenCouvreRequis =
                scopeToken.equals(scopeRequis)
                        || scopeToken.equals("/**")
                        || scopeRequis.startsWith(
                        scopeToken.replace("/**", "")
                );

        return urlDansToken && tokenCouvreRequis;
    }
}
