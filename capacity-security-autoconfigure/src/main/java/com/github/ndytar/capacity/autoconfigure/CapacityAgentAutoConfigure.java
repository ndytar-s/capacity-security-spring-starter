package com.github.ndytar.capacity.autoconfigure;

import com.github.ndytar.capacity.agentic.*;
import com.github.ndytar.capacity.auth.CapacityDecision;
import com.github.ndytar.capacity.chaine.CapacityFilter;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;

import java.util.List;
import java.util.Map;

@AutoConfiguration
@ConditionalOnClass()
public class CapacityAgentAutoConfigure {

    @Bean
    @ConditionalOnMissingBean
    public ToolVisibilityFilter toolVisibilityFilter(
            CapacityRequirementRegistry registry,
            CapacityDecision capacityDecision
    ) {
        return new ToolVisibilityFilter(
                registry,
                 capacityDecision
        );
    }
    @Bean
    @ConditionalOnMissingBean
    public SubjectIdStartupValidator subjectIdStartupValidator(ApplicationContext context){
        return new SubjectIdStartupValidator(context);
    }
    @Bean
    @ConditionalOnMissingBean
    public SubjectIdArgumentResolver subjectIdArgumentResolver(){
        return new SubjectIdArgumentResolver();
    }

    @Bean
    @ConditionalOnMissingBean(CapacityToolWrappingFactory.class)
    public CapacityToolWrappingFactory capacityToolWrappingFactory(CapacityRequirementRegistry registry,
                                                      CapacityDecision capacityDecision){
        return new CapacityToolWrappingFactory( registry,
                capacityDecision);
    }

    @Bean
    @ConditionalOnMissingBean
    public CapacityRequirementRegistry capacityRequirementRegistry(){
        return new CapacityRequirementRegistry();
    }

    @Bean
    @ConditionalOnMissingBean
    public AgentContextService agentContextService(
            Map<String, List<ToolCallback>> toolsParAgent,
            ToolVisibilityFilter visibilityFilter,
            @Value("${capacity.agentic.expose-all-tools:false}") boolean exposeAllTools
    ){return new AgentContextService( toolsParAgent, visibilityFilter, exposeAllTools);}

    @Bean
    @ConditionalOnMissingBean
    public AgentContextMessageArgumentResolver agentContextMessageArgumentResolver(
            AgentContextService agentContextService
    ){return new AgentContextMessageArgumentResolver( agentContextService);}

    @Bean
    @ConditionalOnMissingBean
    public AgentContextArgumentResolver agentContextArgumentResolver(
            AgentContextService agentContextService
    ){return new AgentContextArgumentResolver( agentContextService);}



}
