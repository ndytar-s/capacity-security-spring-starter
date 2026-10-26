package com.github.ndytar.capacity.audit;
public interface AuditEventHandler {

    void handle(SecurityAuditEvent event);

}
