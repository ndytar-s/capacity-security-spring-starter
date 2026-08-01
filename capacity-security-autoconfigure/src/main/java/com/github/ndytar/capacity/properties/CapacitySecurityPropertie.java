package com.github.ndytar.capacity.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;


@ConfigurationProperties(prefix = "capacity.security")
public class CapacitySecurityPropertie {
   private String allowedapi;
   private String mtls;
   public String getAllowedapi() {
        return allowedapi;
    }
    public void setAllowedapi(String allowedapi) {
       this.allowedapi = allowedapi;
    }

    public String getMtls() {
        return mtls;
    }

    public void setMtls(String mtls) {
        this.mtls = mtls;
    }
}
