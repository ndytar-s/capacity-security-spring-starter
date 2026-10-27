package com.github.ndytar.capacity.config;


import com.github.ndytar.capacity.agentic.CapacityToolWrappingFactory;
import com.github.ndytar.capacity.annotation.AgentToolsSource;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Infrastructure — ne JAMAIS modifier.
 * Registre automatiquement le bean agrégé @Primary
 * à partir de tous les beans annotés @AgentToolsSource.
 */
@AutoConfiguration(afterName =
        "org.springframework.ai.model.chat.client.autoconfigure.ChatClientAutoConfiguration")
@ConditionalOnClass(ToolCallback.class)
public class AgentToolsAutoConfig {

    @Bean
    @Primary
    public Map<String, List<ToolCallback>> toolsParAgent(ApplicationContext ctx) {
        Map<String, List<ToolCallback>> merged = new HashMap<>();
        ctx.getBeansWithAnnotation(AgentToolsSource.class).values().stream()
                .filter(v -> v instanceof Map<?, ?>)
                .map(this::toToolsMap)
                .forEach(m -> m.forEach((agent, tools) ->
                        merged.computeIfAbsent(agent, k -> new ArrayList<>()).addAll(tools)));
        return merged;
    }

    @SuppressWarnings("unchecked")
    private Map<String, List<ToolCallback>> toToolsMap(Object bean) {
        return (Map<String, List<ToolCallback>>) bean;
    }

    @Bean
    @ConditionalOnBean(ChatClient.Builder.class)
    @ConditionalOnMissingBean(ChatClient.class)
    public ChatClient agentManager(ChatClient.Builder builder,
                                   CapacityToolWrappingFactory factory) {
        return builder
                .defaultSystem(factory.composerSystemPrompt("""
                        Tu es un assistant.
                        Pour toute donnée selon la démande, utilise les outils disponibles.
                        Si aucun outil ne correspond à la demande, dis simplement que tu n'as pas d'outil pour cela.
                        Ne prétends jamais avoir vérifié des droits ou des données sans avoir appelé un outil afin de répondre.
                        """))
                .build();
    }
}