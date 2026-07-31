package com.github.ndytar.capacity.properties;


import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "capacity.security.oauth")
public class CapacitySecurityAoautProperties {

    // Valeurs par défaut (standard OAuth2)
    private String headername = "Authorization";
    private String prefix = "Bearer ";

    public String getHeaderName() { return headername; }
    public void setHeaderName(String headername) { this.headername = headername; }

    public String getPrefix() { return prefix; }
    public void setPrefix(String prefix) { this.prefix = prefix; }
}

