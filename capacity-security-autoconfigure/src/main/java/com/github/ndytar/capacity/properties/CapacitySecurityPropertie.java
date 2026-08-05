package com.github.ndytar.capacity.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

import java.util.Arrays;
import java.util.List;


@ConfigurationProperties(prefix = "capacity.security")
public class CapacitySecurityPropertie {
    private String mtls;
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

    public List<IpAddressMatcher> getAllowedIps() {
        return allowedIps;
    }
    public void setAllowedapi(String allowedapi) {}

    public String getMtls() {
        return mtls;
    }

    public void setMtls(String mtls) {
        this.mtls = mtls;
    }
}
