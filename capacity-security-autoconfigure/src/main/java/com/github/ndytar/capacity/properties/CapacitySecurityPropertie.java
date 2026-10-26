package com.github.ndytar.capacity.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

@Component
@ConfigurationProperties(prefix = "capacity.security")
public class CapacitySecurityPropertie {

   private boolean logAudit;
    private List<IpAddressMatcher> allowedIps = List.of();

    // Le setter accepte la String (séparée par des virgules) et crée les Matchers
    public void setAllowedIps(String allowedIpsConfig) {
        if (allowedIpsConfig != null && !allowedIpsConfig.isBlank()) {
            this.allowedIps = Arrays.stream(allowedIpsConfig.split(","))
                    .map(String::trim)
                    .map(IpAddressMatcher::new)
                    .toList();
        }
    }

    public boolean isLogAudit() {
        return logAudit;
    }

    public void setLogAudit(boolean logAudit) {
        this.logAudit = logAudit;
    }

    public List<IpAddressMatcher> getAllowedIps() {
        return allowedIps;
    }
    public void setAllowedapi(String allowedapi) {}


}
