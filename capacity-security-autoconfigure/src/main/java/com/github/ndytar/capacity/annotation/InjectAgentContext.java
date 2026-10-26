package com.github.ndytar.capacity.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Posée sur un paramètre de type AgentContext, dans un @RestController ou
 * un @MessageMapping (WebSocket/STOMP). Résolue par
 * AgentContextArgumentResolver (MVC) ou AgentContextMessageArgumentResolver
 * (WebSocket) selon la pile, toutes deux basées sur AgentContextService.
 *
 * agent() identifie quel jeu de tools filtrer, pour le cas où plusieurs
 * agents (virement, rapports...) coexistent dans l'application.
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
public @interface InjectAgentContext {
    String agent() default "";
}
