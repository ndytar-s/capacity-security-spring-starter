package com.github.ndytar.capacity.services;


import  com.github.ndytar.capacity.aop.OauthUserInfo;

public interface ExternalOauthVerifier {
    OauthUserInfo verify(String rawToken);
}
