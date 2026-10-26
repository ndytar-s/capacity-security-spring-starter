package com.github.ndytar.capacity.agentic;

import com.github.ndytar.capacity.auth.CapacityAuth;
import org.springframework.ai.tool.ToolCallback;

import java.util.List;
import java.util.Map;

/**
 * Regroupe ce qu'un contrôleur (REST ou WebSocket) a besoin de passer à
 * ChatClient.prompt(...) pour une requête donnée : la liste de capacités
 * détenues, les tools déjà filtrés selon ces capacités, et la Map prête à
 * passer telle quelle à toolContext(...).
 */
public record AgentContext(
        List<CapacityAuth> capacites,
        List<ToolCallback> toolsVisibles,
        Map<String, Object> toolContext
) {}