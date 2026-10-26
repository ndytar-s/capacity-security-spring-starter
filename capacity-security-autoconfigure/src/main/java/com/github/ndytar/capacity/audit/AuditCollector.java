package com.github.ndytar.capacity.audit;

public interface AuditCollector {

    void record(AuditEvent event);

}