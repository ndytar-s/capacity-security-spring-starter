package com.github.ndytar.capacity.customclaims;

public final class CustomClaimsContextHolder {

    private static final ThreadLocal<CustomClaimsContext> CONTEXT = ThreadLocal.withInitial(CustomClaimsContext::new);

    private CustomClaimsContextHolder() {
    }

    public static CustomClaimsContext claims() {
        return CONTEXT.get();
    }

    public static void clear() {
        CONTEXT.remove();
    }
}
