package com.github.ndytar.capacity.autoconfigure;


import com.github.ndytar.capacity.auth.CapacityAuthManager;
import com.github.ndytar.capacity.filter.CapacityFilter;
import com.github.ndytar.capacity.properties.CapacityProperties;
import com.github.ndytar.capacity.service.JwtService;
import com.github.ndytar.capacity.service.MacaroonService;
import com.github.ndytar.capacity.service.TokenRedisService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.web.SecurityFilterChain;

@AutoConfiguration
@ConditionalOnClass(SecurityFilterChain.class)
@EnableConfigurationProperties(CapacityProperties.class)
public class CapacitySecurityAutoConfiguration {
    @Bean
    @ConditionalOnMissingBean
    public CapacityFilter capacityFilter(
            JwtService jwtService,
            MacaroonService macaroonService,
            CapacityProperties properties) {

        CapacityFilter filter = new CapacityFilter(jwtService, macaroonService);
        filter.setHEADER(properties.getJwt().getHeaderName());
        return filter;
    }
    @Bean
    @ConditionalOnMissingBean
    public JwtService jwtService(TokenRedisService tokenRedisService,
                                 CapacityProperties properties) {
        return new JwtService(tokenRedisService, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public MacaroonService macaroonService(CapacityProperties properties,
                                           TokenRedisService tokenRedisService) {
        return new MacaroonService(properties, tokenRedisService);
    }

    @Bean
    @ConditionalOnMissingBean
    public TokenRedisService tokenRedisService(StringRedisTemplate redisTemplate) {
        return new TokenRedisService(redisTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    public CapacityAuthManager capacityAuthManager() {
        return new CapacityAuthManager();
    }

    @Bean
    @ConditionalOnMissingBean
    public CapacityFilter capacityFilter(
            JwtService jwtService,
            MacaroonService macaroonService) {
        return new CapacityFilter(jwtService, macaroonService);
    }

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain capacityFilterChain(
            org.springframework.security.config.annotation.web.builders.HttpSecurity http,
            CapacityFilter capacityFilter,
            CapacityAuthManager capacityAuthManager) throws Exception {

        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s
                        .sessionCreationPolicy(
                                org.springframework.security.config.http.SessionCreationPolicy.STATELESS))
                .anonymous(anonymous -> anonymous.disable())
                .addFilterBefore(
                        capacityFilter,
                        org.springframework.security.web.authentication
                                .UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .anyRequest()
                        .access(capacityAuthManager));

        return http.build();
    }
}