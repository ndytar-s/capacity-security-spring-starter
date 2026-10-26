package com.github.ndytar.capacity.proof.dPop;

import java.time.Duration;

public class NoOpJtiStore implements JtiStore {
    @Override
    public boolean tryRegister(String jti, Duration ttl) { return true; } // mode dégradé, pas d'anti-rejeu
}