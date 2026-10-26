package com.github.ndytar.capacity.agentic;


import com.github.ndytar.capacity.annotation.RequiresCapacity;
import com.github.ndytar.capacity.auth.CapacityAuth;
import com.github.ndytar.capacity.auth.CapacityDecision;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Filtre la liste de tools AVANT de la donner au LLM, en fonction des
 * capacités détenues pour cette requête précise. Utilise CapacityDecision.couvre(...),
 * une vérification pure sans révocation ni audit : on ne veut jamais
 * consommer une capacité one-time juste pour décider si un tool doit être
 * montré au modèle.
 *
 * Ce filtrage est une optimisation UX/exposition, pas la garantie de
 * sécurité : CapacityAwareToolCallback reste la vraie barrière, y compris
 * si ce filtre était contourné ou mal configuré.
 */

/**
 * Filtre la liste de tools AVANT de la donner au LLM, selon les capacités
 * détenues pour cette requête. Utilise CapacityDecision.couvre(...), une
 * vérification pure : aucune révocation one-time, aucun audit.
 *
 * Les logs "Capacité reçue" et "Tool ... -> visible/masqué" servent à comprendre
 * pourquoi un tool apparaît ou non. À repasser en debug une fois les tests finis.
 *
 * ADAPTER : req.action() doit correspondre au nom réel dans ton annotation.
 */


/**
 * Filtre la liste de tools AVANT de la donner au LLM, selon les capacités détenues.
 * Vérification pure (CapacityDecision.couvre) : aucune révocation, aucun audit.
 * Un tool qui déclare @SubjectId n'est visible que si une capacité personnelle le couvre.
 *
 * ADAPTER : req.action() doit correspondre au nom réel dans ton annotation.
 */

public class ToolVisibilityFilter {

    private static final Logger log = LoggerFactory.getLogger(ToolVisibilityFilter.class);

    private final CapacityRequirementRegistry registry;
    private final CapacityDecision capacityDecision;

    public ToolVisibilityFilter(CapacityRequirementRegistry registry,
                                CapacityDecision capacityDecision) {
        this.registry = registry;
        this.capacityDecision = capacityDecision;
    }

    public List<ToolCallback> filtrer(List<ToolCallback> toolsSecurises, List<CapacityAuth> capacites) {
        capacites.forEach(c -> log.info("Capacité reçue : scope={}, actions={}, personnelle={}",
                c.getResourceScope(), c.getActions(), c.isPersonnel()));
log.info("All tools {}",toolsSecurises.stream().map(t -> t.getToolDefinition().name()).toList());
        return toolsSecurises.stream()
                .filter(tool -> {
                    String toolName = tool.getToolDefinition().name();
                    RequiresCapacity req = registry.get(toolName);

                    if (req == null) {
                        log.info("Tool {} sans exigence déclarée -> visible", toolName);
                        return true;
                    }

                    String action = !req.actions().isEmpty() ? req.actions() : "READ";
                    boolean sujetRequis = registry.subjectParam(toolName) != null;
                    boolean visible = capacityDecision.couvre(
                            capacites, req.resourcePattern(), req.resourcePattern(), action, sujetRequis);

                    log.info("Tool {} exige scope={}, action={}, sujet={} -> {}",
                            toolName, req.resourcePattern(), action, sujetRequis,
                            visible ? "visible" : "masqué");
                    return visible;
                })
                .toList();
    }
}
