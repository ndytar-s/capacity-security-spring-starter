package com.github.ndytar.capacity.agentic;

import com.github.ndytar.capacity.annotation.SubjectId;
import com.github.ndytar.capacity.auth.CapacityAuth;
import com.github.ndytar.capacity.exception.CapacityDeniedException;
import org.springframework.core.MethodParameter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/**
 * Voie REST : fournit la valeur des paramètres @SubjectId depuis la capacité
 * présente dans le SecurityContext (posée par CapacityFilter), jamais depuis la requête.
 *
 * À enregistrer dans WebMvcConfigurer.addArgumentResolvers. Un resolver personnalisé
 * passe avant celui qui lie les paramètres simples à ?nom=valeur ; SubjectIdStartupValidator
 * interdit en plus tout autre mode de liaison sur ce paramètre.
 */

public class SubjectIdArgumentResolver implements HandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        Class<?> type = parameter.getParameterType();
        return parameter.hasParameterAnnotation(SubjectId.class)
                && (type == Long.class || type == long.class);
    }

    @Override
    public Object resolveArgument(MethodParameter parameter,
                                  ModelAndViewContainer mavContainer,
                                  NativeWebRequest webRequest,
                                  WebDataBinderFactory binderFactory) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (!(auth instanceof CapacityAuth capacite)) {
            throw new CapacityDeniedException("Aucune capacité disponible pour résoudre le sujet");
        }
        return capacite.getSujectId();
    }
}

