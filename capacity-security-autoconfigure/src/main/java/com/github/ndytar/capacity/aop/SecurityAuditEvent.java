package com.github.ndytar.capacity.aop;

import java.time.Instant;
import java.util.List;

public record SecurityAuditEvent(
        AuditType AuditType,
        String username,
        String resource,
        String evenement,
        List<String> actionsList,
        Instant timestamp) {

}
