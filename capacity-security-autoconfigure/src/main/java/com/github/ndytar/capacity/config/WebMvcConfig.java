package com.github.ndytar.capacity.config;


import com.github.ndytar.capacity.agentic.AgentContextArgumentResolver;
import com.github.ndytar.capacity.agentic.SubjectIdArgumentResolver;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;




@AutoConfiguration
public class WebMvcConfig implements WebMvcConfigurer {

    private final SubjectIdArgumentResolver subjectIdArgumentResolver;
    private final AgentContextArgumentResolver agentContextArgumentResolver;


    public WebMvcConfig(SubjectIdArgumentResolver subjectIdArgumentResolver, AgentContextArgumentResolver agentContextArgumentResolver) {
        this.subjectIdArgumentResolver = subjectIdArgumentResolver;
        this.agentContextArgumentResolver = agentContextArgumentResolver;
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(subjectIdArgumentResolver);
        resolvers.add(agentContextArgumentResolver);
    }
}
