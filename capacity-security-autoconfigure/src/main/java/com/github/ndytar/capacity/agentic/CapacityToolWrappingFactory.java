package com.github.ndytar.capacity.agentic;


import com.github.ndytar.capacity.auth.CapacityDecision;
import org.springframework.ai.support.ToolCallbacks;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;


public class CapacityToolWrappingFactory {

    private static final String CONSIGNE_SECURITE = """
            Si un outil échoue avec une erreur d'autorisation ou de capacité,
            informe l'utilisateur qu'il n'a pas les droits nécessaires,
            sans jamais révéler de détails techniques (scopes, tokens, messages internes).
            """;

    private final CapacityRequirementRegistry registry;
    private final CapacityDecision capacityDecision;

    public CapacityToolWrappingFactory(CapacityRequirementRegistry registry,
                                       CapacityDecision capacityDecision) {
        this.registry = registry;
        this.capacityDecision = capacityDecision;
    }

    /**
     * Reçoit directement les objets de tools du développeur (ex. new VirementTools()),
     * enregistre leurs exigences de capacité, les convertit en ToolCallback et
     * enveloppe chacun. Une seule étape pour le dev, plus de ToolCallbacks.from(...)
     * à écrire de son côté.
     */
    public List<ToolCallback> wrapper(Object... toolBeans) {
        List<ToolCallback> resultat = new ArrayList<>();
        for (Object bean : toolBeans) {
            registry.enregistrer(bean);
            for (ToolCallback tool : ToolCallbacks.from(bean)) {
                resultat.add(new CapacityAwareToolCallback(tool, registry, capacityDecision));
            }
        }
        return resultat;
    }

    public String composerSystemPrompt(String promptMetier) {
        return promptMetier + "\n\n" + CONSIGNE_SECURITE;
    }
}


