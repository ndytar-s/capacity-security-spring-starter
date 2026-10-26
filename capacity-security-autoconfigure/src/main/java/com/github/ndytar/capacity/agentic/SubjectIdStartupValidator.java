package com.github.ndytar.capacity.agentic;

import com.github.ndytar.capacity.annotation.SubjectId;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.context.ApplicationContext;
import org.springframework.core.MethodParameter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.lang.annotation.Annotation;
import java.util.List;

/**
 * Échoue au démarrage si un paramètre @SubjectId d'un endpoint REST :
 *  - n'est pas de type Long/long ;
 *  - porte aussi un mode de liaison client (@RequestParam, @PathVariable, @RequestBody...),
 *    ce qui laisserait le client choisir l'identifiant.
 * S'exécute après la création de tous les singletons, donc sans risque de cycle de beans.
 */

public class SubjectIdStartupValidator implements SmartInitializingSingleton {

    private static final List<Class<? extends Annotation>> LIAISONS_CLIENT = List.of(
            RequestParam.class, PathVariable.class, RequestBody.class, RequestHeader.class,
            RequestAttribute.class, ModelAttribute.class, CookieValue.class, RequestPart.class,
            MatrixVariable.class, SessionAttribute.class);

    private final ApplicationContext context;

    public SubjectIdStartupValidator(ApplicationContext context) {
        this.context = context;
    }

    @Override
    public void afterSingletonsInstantiated() {
        context.getBeansOfType(RequestMappingHandlerMapping.class).values()
                .forEach(mapping -> mapping.getHandlerMethods().values().forEach(this::verifier));
    }

    private void verifier(HandlerMethod handlerMethod) {
        for (MethodParameter p : handlerMethod.getMethodParameters()) {
            if (!p.hasParameterAnnotation(SubjectId.class)) continue;

            Class<?> type = p.getParameterType();
            if (type != Long.class && type != long.class) {
                throw new IllegalStateException("@SubjectId doit être de type Long : " + handlerMethod);
            }
            for (Class<? extends Annotation> liaison : LIAISONS_CLIENT) {
                if (p.hasParameterAnnotation(liaison)) {
                    throw new IllegalStateException("@SubjectId ne peut pas être combiné avec @"
                            + liaison.getSimpleName() + " : " + handlerMethod);
                }
            }
        }
    }
}