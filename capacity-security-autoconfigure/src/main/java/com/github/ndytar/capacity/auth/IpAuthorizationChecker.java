package com.ndytar.reveseEngineering.auth;

import com.ndytar.reveseEngineering.annotation.AllowedIp;
import com.ndytar.reveseEngineering.properties.CapacitySecurityPropertie;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.security.autoconfigure.SecurityProperties;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;

@Component
public class IpAuthorizationChecker {

    private static final Logger log = LoggerFactory.getLogger(IpAuthorizationChecker.class);
    private final CapacitySecurityPropertie securityProperties;

    // Injection automatique par constructeur grâce à @Component
    public IpAuthorizationChecker(CapacitySecurityPropertie securityProperties) {
        this.securityProperties = securityProperties;
    }

    public boolean verifierIp(HttpServletRequest request, HandlerMethod handler) {
        // 1. On vérifie si la méthode (ou sa classe) porte l'annotation
        AllowedIp allowedIpAnnotation = handler.getMethodAnnotation(AllowedIp.class);

        // Si l'annotation n'est pas présente, on autorise l'accès (pas de restriction IP sur cette route)
        if (allowedIpAnnotation == null) {
            return true;
        }

        // 2. Si l'annotation est présente, on valide l'IP du client
        String clientIp = request.getRemoteAddr();

        boolean isIpAllowed = securityProperties.getAllowedIps().stream()
                .anyMatch(matcher -> matcher.matches(clientIp));

        if (!isIpAllowed) {
            log.warn("Accès refusé pour la route [{}] : l'IP client [{}] n'est pas autorisée.",
                    request.getRequestURI(), clientIp);
            return false;
        }

        return true;
    }
}

