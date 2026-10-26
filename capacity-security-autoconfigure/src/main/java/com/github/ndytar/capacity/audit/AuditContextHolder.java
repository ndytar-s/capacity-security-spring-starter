package com.github.ndytar.capacity.audit;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public final class AuditContextHolder {

    private static final ThreadLocal<AuditContext> CONTEXT =
            new ThreadLocal<>();

    private AuditContextHolder() {
    }

    public static void set(AuditContext context) {
        CONTEXT.set(context);
    }

    public static AuditContext get() {
        return CONTEXT.get();
    }

    public static void clear() {
        CONTEXT.remove();
    }
}
