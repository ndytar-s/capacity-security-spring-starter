package com.github.ndytar.capacity.audit;

import java.util.List;

public record SecurityAuditEvent(
        List<AuditEvent> events
) {}
