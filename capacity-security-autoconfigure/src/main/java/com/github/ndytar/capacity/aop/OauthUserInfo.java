package com.github.ndytar.capacity.aop;

public class OauthUserInfo {
    private final String userId;
    private final String email;

    public OauthUserInfo(String userId, String email) {
        this.userId = userId;
        this.email = email;
    }

    public String getUserId() { return userId; }
    public String getEmail() { return email; }
}
