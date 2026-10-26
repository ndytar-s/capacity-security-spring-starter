package com.github.ndytar.capacity.agentic;



import com.github.ndytar.capacity.annotation.InjectAgentContext;
import com.github.ndytar.capacity.auth.CapacityAuth;
import org.springframework.core.MethodParameter;
import org.springframework.messaging.Message;
import org.springframework.messaging.handler.invocation.HandlerMethodArgumentResolver;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * ESQUISSE, PAS VALIDÉE — deux points à vérifier avant d'utiliser ceci en
 * production :
 *
 * 1. Interface différente de la pile MVC : ici
 *    org.springframework.messaging.handler.invocation.HandlerMethodArgumentResolver,
 *    avec resolveArgument(MethodParameter, Message<?>), pas le même contrat
 *    que AgentContextArgumentResolver (fichier 18). Les deux portent le même
 *    nom d'interface mais viennent de packages différents, ne pas les
 *    confondre à l'enregistrement.
 *
 * 2. CapacityFilter (un jakarta.servlet.Filter) ne s'exécute jamais sur les
 *    messages STOMP après la poignée de main initiale (upgrade HTTP -> WS).
 *    Il n'y a donc PAS d'attribut de requête à lire ici. Il faut un
 *    ChannelInterceptor séparé, qui s'exécute sur le CONNECT STOMP, relit
 *    les tokens de capacité (probablement passés en header STOMP plutôt
 *    qu'en header HTTP), refait la même construction de liste que
 *    CapacityFilter.construireListeCapacites(...), et stocke le résultat
 *    dans les attributs de session STOMP
 *    (SimpMessageHeaderAccessor.getSessionAttributes()), pas dans la
 *    requête HTTP.
 *
 * Ce ChannelInterceptor n'est pas écrit ici : c'est une pièce distincte,
 * de la taille de CapacityFilter lui-même, pas une adaptation triviale.
 * Ne pas fusionner CapacityFilter et cet interceptor : le premier reste
 * lié au cycle de vie Servlet, le second au cycle de vie STOMP.
 */

public class AgentContextMessageArgumentResolver implements HandlerMethodArgumentResolver {

    public static final String SESSION_ATTR_CAPACITY_LIST = "AGENT_CAPACITY_LIST";

    private final AgentContextService agentContextService;

    public AgentContextMessageArgumentResolver(AgentContextService agentContextService) {
        this.agentContextService = agentContextService;
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(InjectAgentContext.class)
                && parameter.getParameterType().equals(AgentContext.class);
    }

    @Override
    @SuppressWarnings("unchecked")
    public Object resolveArgument(MethodParameter parameter, Message<?> message) {
        InjectAgentContext annotation = parameter.getParameterAnnotation(InjectAgentContext.class);

        SimpMessageHeaderAccessor accessor =
                SimpMessageHeaderAccessor.wrap(message);

        List<CapacityAuth> capacites = (List<CapacityAuth>)
                (accessor.getSessionAttributes() != null
                        ? accessor.getSessionAttributes().get(SESSION_ATTR_CAPACITY_LIST)
                        : null);

        return agentContextService.construire(annotation.agent(), capacites);
    }
}

