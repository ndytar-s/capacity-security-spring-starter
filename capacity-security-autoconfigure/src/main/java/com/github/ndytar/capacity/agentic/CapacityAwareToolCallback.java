package com.github.ndytar.capacity.agentic;


import com.github.ndytar.capacity.annotation.RequiresCapacity;
import com.github.ndytar.capacity.auth.CapacityAuth;
import com.github.ndytar.capacity.auth.CapacityDecision;
import com.github.ndytar.capacity.exception.CapacityDeniedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.model.ToolContext;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.definition.ToolDefinition;
import org.springframework.ai.tool.execution.ToolExecutionException;
import org.springframework.ai.tool.metadata.ToolMetadata;
import tools.jackson.databind.json.JsonMapper;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Seconde barrière : vérifie la capacité au moment où le LLM appelle réellement
 * un tool. Les logs "autorisé" et "refusé" rendent chaque décision visible dans
 * la console, y compris quand le filtre de visibilité est désactivé (mode test).
 *
 * ADAPTER : req.action() doit correspondre au nom réel dans ton annotation.
 */

/**
 * Seconde barrière : vérifie la capacité au moment où le LLM appelle un tool, et,
 * pour un tool qui déclare @SubjectId, injecte l'identifiant du sujet porté par la
 * capacité retenue. Toute valeur proposée par le LLM pour ce paramètre est écrasée.
 *
 * LIMITE CONNUE : le paramètre @SubjectId reste visible dans le schéma JSON envoyé au
 * LLM (il peut donc demander cette valeur à l'utilisateur). Sa valeur est sans effet.
 * JSON : Jackson 3 (tools.jackson.databind.json.JsonMapper), celui de Spring Boot 4.
 * JsonParser de Spring AI est déprécié pour suppression et n'est donc pas utilisé.
 * ADAPTER : req.action() doit correspondre au nom réel dans ton annotation.
 */
public class CapacityAwareToolCallback implements ToolCallback {

    private static final Logger log = LoggerFactory.getLogger(CapacityAwareToolCallback.class);

    public static final String CONTEXT_KEY_CAPACITIES = "capacities";

    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    private final ToolCallback delegate;
    private final CapacityRequirementRegistry registry;
    private final CapacityDecision capacityDecision;

    public CapacityAwareToolCallback(ToolCallback delegate,
                                     CapacityRequirementRegistry registry,
                                     CapacityDecision capacityDecision) {
        this.delegate = delegate;
        this.registry = registry;
        this.capacityDecision = capacityDecision;
    }

    @Override
    public ToolDefinition getToolDefinition() {
        return delegate.getToolDefinition();
    }

    @Override
    public ToolMetadata getToolMetadata() {
        return delegate.getToolMetadata();
    }

    /** Sans ToolContext, aucune capacité disponible : refus (fail closed) pour tout tool protégé. */
    @Override
    public String call(String toolInput) {
        String toolName = delegate.getToolDefinition().name();
        if (registry.get(toolName) == null) {
            return delegate.call(toolInput);
        }
        log.warn("Tool {} refusé : appel sans contexte de capacités", toolName);
        throw new ToolExecutionException(delegate.getToolDefinition(),
                new CapacityDeniedException("Appel sans contexte de capacités refusé : " + toolName));
    }

    @Override
    @SuppressWarnings("unchecked")
    public String call(String toolInput, ToolContext context) {

        String toolName = delegate.getToolDefinition().name();
        RequiresCapacity req = registry.get(toolName);

        if (req == null) {
            log.info("Tool {} sans exigence déclarée : exécuté sans contrôle", toolName);
            return delegate.call(toolInput, context);
        }

        try {
            List<CapacityAuth> capacites =
                    (List<CapacityAuth>) context.getContext().get(CONTEXT_KEY_CAPACITIES);
            if (capacites == null || capacites.isEmpty()) {
                throw new CapacityDeniedException("Aucune capacité disponible dans le contexte pour : " + toolName);
            }

            String actionRequise = !req.actions().isEmpty() ? req.actions() : "READ";
            String subjectParam = registry.subjectParam(toolName);
            boolean sujetRequis = subjectParam != null;

            CapacityAuth retenue = capacityDecision.resoudre(
                    capacites, req.resourcePattern(), req.resourcePattern(), actionRequise, sujetRequis);

            String input = toolInput;
            if (sujetRequis) {
                input = injecterSujet(toolInput, subjectParam, retenue.getSujectId());
            }

            log.info("Tool {} AUTORISÉ par la capacité scope={}, actions={}",
                    toolName, retenue.getResourceScope(), retenue.getActions());
            return delegate.call(input, context);

        } catch (CapacityDeniedException e) {
            // détail complet dans les logs serveur, message générique pour le LLM
            log.warn("Tool {} REFUSÉ : {}", toolName, e.getMessage());
            throw new ToolExecutionException(delegate.getToolDefinition(),
                    new CapacityDeniedException("Accès refusé : droits insuffisants pour l'outil " + toolName));
        }
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private String injecterSujet(String toolInput, String paramName, Long sujet) {
        try {
            Map<String, Object> args = (toolInput == null || toolInput.isBlank())
                    ? new HashMap<>()
                    : new HashMap<>((Map) MAPPER.readValue(toolInput, Map.class));
            args.put(paramName, sujet);   // écrase toute valeur proposée par le LLM
            return MAPPER.writeValueAsString(args);
        } catch (RuntimeException e) {
            // entrée illisible : on refuse plutôt que d'appeler le tool sans sujet
            throw new CapacityDeniedException("Entrée du tool illisible, sujet non injecté");
        }
    }
}
