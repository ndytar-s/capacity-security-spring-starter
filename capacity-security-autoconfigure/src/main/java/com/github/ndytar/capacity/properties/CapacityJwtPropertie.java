package com.github.ndytar.capacity.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "capacity.jwt")
public class CapacityJwtPropertie {
   private long duration=900000;
   private long refduration=604800000;
   private  String headername = "X-Capacity-Token";
   private String headerrefname = "X-CapacityRef-Token";
   private String keysecret;

    public long getDuration() {
        return duration;
    }

    public void setDuration(long duration) {
        this.duration = duration;
    }

    public long getRefduration() {
        return refduration;
    }

    public void setRefduration(long refduration) {
        this.refduration = refduration;
    }

    public String getHeadername() {
        return headername;
    }

    public void setHeadername(String headername) {
        this.headername = headername;
    }

    public String getHeaderrefname() {
        return headerrefname;
    }

    public void setHeaderrefname(String headerrefname) {
        this.headerrefname = headerrefname;
    }

    public String getKeysecret() {
        return keysecret;
    }

    public void setKeysecret(String keysecret) {
        this.keysecret = keysecret;
    }
}
