package com.github.ndytar.capacity.agentic;



import com.github.ndytar.capacity.annotation.InjectAgentContext;
import com.github.ndytar.capacity.auth.CapacityAuth;
import com.github.ndytar.capacity.chaine.CapacityFilter;
import com.github.ndytar.capacity.exception.ApiExceptions;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.MethodParameter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import java.util.List;

/**
 * org.springframework.web.method.support.HandlerMethodArgumentResolver
 * (pile MVC classique). Un contrôleur REST déclare simplement :
 *
 *   @PostMapping("/chat")
 *   public String chat(@InjectAgentContext(agent = "virement") AgentContext ctx, @RequestBody String input)
 *
 * et n'a plus jamais à lire request.getAttribute(...) ni à appeler
 * ToolVisibilityFilter lui-même.
 */

public class AgentContextArgumentResolver implements HandlerMethodArgumentResolver {

    private final AgentContextService agentContextService;

    public AgentContextArgumentResolver(AgentContextService agentContextService) {
        this.agentContextService = agentContextService;
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(InjectAgentContext.class)
                && parameter.getParameterType().equals(AgentContext.class);
    }

    @Override
    @SuppressWarnings("unchecked")
    public Object resolveArgument(MethodParameter parameter,
                                  ModelAndViewContainer mavContainer,
                                  NativeWebRequest webRequest,
                                  WebDataBinderFactory binderFactory) {

        InjectAgentContext annotation = parameter.getParameterAnnotation(InjectAgentContext.class);
        HttpServletRequest request = (HttpServletRequest) webRequest.getNativeRequest();
       String agentName = webRequest.getParameter("X-Agent");
        if (agentName == null)
            throw  ApiExceptions.parametreInvalide("Agent name incorrect information , Parameter: X-Agent ");
        agentName = (annotation != null && !annotation.agent().isEmpty()) ? annotation.agent() : agentName;
        List<CapacityAuth> capacites =
                (List<CapacityAuth>) request.getAttribute(CapacityFilter.ATTR_CAPACITY_LIST);

        return agentContextService.construire(agentName, capacites);
    }
}
