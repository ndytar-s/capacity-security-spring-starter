package com.github.ndytar.capacity.audit;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j

public class DefaultAuditCollector implements AuditCollector {

    @Override
    public void record(AuditEvent event) {

        AuditContext context = AuditContextHolder.get();

        if (context != null) {
            context.add(event);
        }
    }
}