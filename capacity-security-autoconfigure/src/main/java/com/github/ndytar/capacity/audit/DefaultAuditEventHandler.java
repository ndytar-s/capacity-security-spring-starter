package com.github.ndytar.capacity.audit;

import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

public class DefaultAuditEventHandler
        implements AuditEventHandler {

    private final LogAuditSystem logAuditSystem;

    public DefaultAuditEventHandler(
            LogAuditSystem logAuditSystem) {

        this.logAuditSystem = logAuditSystem;
    }

    @EventListener
    @Override
    public void handle(SecurityAuditEvent event) {
        logAuditSystem.log(event.events());
    }
}