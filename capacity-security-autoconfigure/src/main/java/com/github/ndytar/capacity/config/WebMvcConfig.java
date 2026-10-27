package com.github.ndytar.capacity.config;


import com.github.ndytar.capacity.agentic.AgentContextArgumentResolver;
import com.github.ndytar.capacity.agentic.SubjectIdArgumentResolver;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

@AutoConfiguration
public class WebMvcConfig implements WebMvcConfigurer {
    private final ObjectProvider<SubjectIdArgumentResolver> subjectIdArgumentResolver;
    private final  ObjectProvider<AgentContextArgumentResolver>   agentContextArgumentResolver;
    public WebMvcConfig(ObjectProvider<SubjectIdArgumentResolver> subjectIdArgumentResolver,  ObjectProvider<AgentContextArgumentResolver> agentContextArgumentResolver) {
        this.subjectIdArgumentResolver = subjectIdArgumentResolver;
        this.agentContextArgumentResolver = agentContextArgumentResolver;
    }
    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        subjectIdArgumentResolver.ifAvailable(resolvers::add);
        agentContextArgumentResolver.ifAvailable(resolvers::add);
    }
}
