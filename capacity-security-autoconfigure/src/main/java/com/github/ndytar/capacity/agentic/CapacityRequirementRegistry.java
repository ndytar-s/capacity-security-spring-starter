package com.github.ndytar.capacity.agentic;



import com.github.ndytar.capacity.annotation.RequiresCapacity;
import com.github.ndytar.capacity.annotation.SubjectId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Scanne, une fois au démarrage, les méthodes annotées @Tool + @RequiresCapacity
 * sur les beans de tools fournis, et indexe le résultat par nom de tool.
 *
 * @Tool.name() peut être vide, auquel cas le nom du tool retenu par
 * Spring AI est le nom de la méthode (comportement du framework, à vérifier
 * contre votre version exacte de spring-ai-model si elle diffère).
 */


/**
 * Indexe, par nom de tool, l'annotation @RequiresCapacity et, le cas échéant, le
 * nom du paramètre @SubjectId. Aucune dépendance injectée (pas de cycle de beans).
 *
 * Échecs au démarrage (fail closed) :
 *  - @SubjectId sans @RequiresCapacity : l'identifiant ne serait jamais injecté et
 *    resterait choisi par le LLM ;
 *  - plusieurs @SubjectId, mauvais type, ou nom de paramètre introuvable (compiler avec -parameters).
 */
public class CapacityRequirementRegistry {

    private static final Logger log = LoggerFactory.getLogger(CapacityRequirementRegistry.class);

    private final Map<String, RequiresCapacity> requirements = new ConcurrentHashMap<>();
    private final Map<String, String> subjectParams = new ConcurrentHashMap<>();

    public void enregistrer(Object toolBean) {
        for (Method m : toolBean.getClass().getDeclaredMethods()) {
            Tool tool = m.getAnnotation(Tool.class);
            if (tool == null) continue;

            String toolName = tool.name().isEmpty() ? m.getName() : tool.name();
            RequiresCapacity req = m.getAnnotation(RequiresCapacity.class);
            String subjectParam = trouverParametreSujet(m, toolName);

            if (req == null) {
                if (subjectParam != null) {
                    throw new IllegalStateException("Tool '" + toolName
                            + "' : @SubjectId exige @RequiresCapacity, sinon l'identifiant serait choisi par le LLM");
                }
                log.warn("Tool '{}' sans @RequiresCapacity : aucun contrôle de capacité ne sera appliqué", toolName);
                continue;
            }

            requirements.put(toolName, req);
            if (subjectParam != null) subjectParams.put(toolName, subjectParam);
        }
    }

    private String trouverParametreSujet(Method m, String toolName) {
        String trouve = null;
        for (Parameter p : m.getParameters()) {
            if (!p.isAnnotationPresent(SubjectId.class)) continue;
            if (trouve != null) {
                throw new IllegalStateException("Tool '" + toolName + "' : un seul @SubjectId autorisé");
            }
            if (p.getType() != Long.class && p.getType() != long.class) {
                throw new IllegalStateException("Tool '" + toolName + "' : @SubjectId doit être de type Long");
            }
            if (!p.isNamePresent()) {
                throw new IllegalStateException("Tool '" + toolName
                        + "' : nom du paramètre introuvable, compiler avec l'option -parameters");
            }
            trouve = p.getName();
        }
        return trouve;
    }

    public RequiresCapacity get(String toolName) {
        return requirements.get(toolName);
    }

    /** Nom du paramètre @SubjectId du tool, ou null si le tool n'en déclare pas. */
    public String subjectParam(String toolName) {
        return subjectParams.get(toolName);
    }
}
