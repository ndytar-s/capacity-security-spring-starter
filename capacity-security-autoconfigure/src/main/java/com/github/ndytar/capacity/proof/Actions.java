package com.github.ndytar.capacity.proof;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public record Actions() {

    private static final ThreadLocal<Set<String>> LOCAL =
            ThreadLocal.withInitial(() -> {
                Set<String> actions = ConcurrentHashMap.newKeySet();
                actions.add("READ");
                return actions;
            });

    // Instance globale
    public static final Actions get = new Actions();

    public Set<String> actions() {
        return LOCAL.get();
    }
}
