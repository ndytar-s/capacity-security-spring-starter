package com.github.ndytar.capacity.agentic;


import com.github.ndytar.capacity.auth.CapacityAuth;
import com.github.ndytar.capacity.exception.ApiExceptions;
import com.github.ndytar.capacity.exception.CapacityDeniedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * Point unique de construction d'AgentContext. Ni les resolvers MVC ni
 * WebSocket ne dupliquent cette logique : ils se contentent d'extraire la
 * List<CapacityAuth> depuis leur transport respectif (attribut de requête
 * HTTP, ou attribut de session STOMP) et de l'apporter ici.
 */

/**
 * Point unique de construction d'AgentContext, indépendant du transport
 * (REST ou WebSocket).
 *
 * capacity.agentic.expose-all-tools=true : MODE TEST UNIQUEMENT. Le filtrage de
 * visibilité est désactivé, le LLM voit tous les tools, et seule la seconde
 * barrière (CapacityAwareToolCallback) protège. Sert à prouver que cette barrière
 * refuse bien un tool hors périmètre. Ne jamais activer en production.
 */

public class AgentContextService {

    private static final Logger log = LoggerFactory.getLogger(AgentContextService.class);

    private final Map<String, List<ToolCallback>> toolsParAgent;
    private final ToolVisibilityFilter visibilityFilter;
    private final boolean exposeAllTools;

    public AgentContextService(Map<String, List<ToolCallback>> toolsParAgent,
                               ToolVisibilityFilter visibilityFilter,
                               @Value("${capacity.agentic.expose-all-tools:false}") boolean exposeAllTools) {
        this.toolsParAgent = toolsParAgent;
        this.visibilityFilter = visibilityFilter;
        this.exposeAllTools = exposeAllTools;
        if (exposeAllTools) {
            log.warn("MODE TEST : tous les tools sont exposés au LLM, seule CapacityAwareToolCallback protège. "
                    + "Ne jamais activer en production.");
        }
    }

    public AgentContext construire(String agent, List<CapacityAuth> capacites) {
        if (capacites == null || capacites.isEmpty()) {
            throw new CapacityDeniedException("Aucune capacité fournie pour l'agent : " + agent);
        }

        List<ToolCallback> toolsSecurises = toolsParAgent.get(agent);
        if (toolsSecurises == null) {
            throw ApiExceptions.parametreInvalide("Agent inconnu : " + agent);
        }

        List<ToolCallback> toolsVisibles = exposeAllTools
                ? toolsSecurises
                : visibilityFilter.filtrer(toolsSecurises, capacites);
        Map<String, Object> toolContext = Map.of(CapacityAwareToolCallback.CONTEXT_KEY_CAPACITIES, capacites);

        return new AgentContext(capacites, toolsVisibles, toolContext);
    }
}
