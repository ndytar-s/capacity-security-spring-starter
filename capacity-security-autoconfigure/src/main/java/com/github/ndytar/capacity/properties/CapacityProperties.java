package com.github.ndytar.capacity.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "capacity")
public class CapacityProperties {

    private Jwt jwt = new Jwt();
    private Macaroon macaroon = new Macaroon();
    private Redis redis = new Redis();

    public Jwt getJwt()             { return jwt; }
    public void setJwt(Jwt jwt)     { this.jwt = jwt; }

    public Macaroon getMacaroon()           { return macaroon; }
    public void setMacaroon(Macaroon m)     { this.macaroon = m; }

    public Redis getRedis()                 { return redis; }
    public void setRedis(Redis redis)       { this.redis = redis; }

    public static class Jwt {
        private String secret;
        private long duree        = 900000;
        private String headerName = "X-Capacity-Token";

        public String getSecret()                   { return secret; }
        public void setSecret(String secret)        { this.secret = secret; }
        public long getDuree()                      { return duree; }
        public void setDuree(long duree)            { this.duree = duree; }
        public String getHeaderName()               { return headerName; }
        public void setHeaderName(String h)         { this.headerName = h; }
    }

    public static class Macaroon {
        private String  location;
        private boolean redisEnabled = false;
        private boolean strict       = true;
        private String  secret;

        public String getLocation()                     { return location; }
        public void setLocation(String location)        { this.location = location; }
        public boolean isRedisEnabled()                 { return redisEnabled; }
        public void setRedisEnabled(boolean r)          { this.redisEnabled = r; }
        public boolean isStrict()                       { return strict; }
        public void setStrict(boolean strict)           { this.strict = strict; }
        public String getSecret()                       { return secret; }
        public void setSecret(String secret)            { this.secret = secret; }
    }

    public static class Redis {
        private boolean enabled = true;
        private String  host    = "localhost";
        private int     port    = 6379;

        public boolean isEnabled()                  { return enabled; }
        public void setEnabled(boolean enabled)     { this.enabled = enabled; }
        public String getHost()                     { return host; }
        public void setHost(String host)            { this.host = host; }
        public int getPort()                        { return port; }
        public void setPort(int port)               { this.port = port; }
    }
}