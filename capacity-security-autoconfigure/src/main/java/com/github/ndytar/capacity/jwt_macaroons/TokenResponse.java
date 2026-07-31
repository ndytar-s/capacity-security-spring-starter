package com.github.ndytar.capacity.jwt_macaroons;

import java.util.Map;

public class TokenResponse {

    private String              username;
    private String              role;
    private Map<String, String> accessTokens;
    private String              refreshToken;
           // nouveau

    public TokenResponse(String username, String role,
                         Map<String, String> accessTokens,
                         String refreshToken) {
        this.username     = username;
        this.role         = role;
        this.accessTokens = accessTokens;
        this.refreshToken = refreshToken;

    }

    public String              getUsername()     { return username; }
    public String              getRole()         { return role; }
    public Map<String, String> getAccessTokens() { return accessTokens; }
    public String              getRefreshToken() { return refreshToken; }

}