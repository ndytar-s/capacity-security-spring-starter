package com.github.ndytar.capacity.proof.dPop;

import java.time.Duration;

public interface JtiStore {
    /** true si le jti est inédit, false s'il a déjà été vu (rejeu). */
    boolean tryRegister(String jti, Duration ttl);
}