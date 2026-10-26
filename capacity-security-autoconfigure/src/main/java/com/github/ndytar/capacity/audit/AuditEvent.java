package com.github.ndytar.capacity.audit;

import java.time.Instant;

public record AuditEvent(

        Instant timestamp,

        String action,

        String resource,

        String subject,

        AuditResult result,

        String reason

) {}
