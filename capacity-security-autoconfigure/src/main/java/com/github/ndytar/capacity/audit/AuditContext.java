package com.github.ndytar.capacity.audit;

import java.util.ArrayList;
import java.util.List;

public class AuditContext {

    private final List<AuditEvent> events =
            new ArrayList<>();

    public void add(AuditEvent event) {
        events.add(event);
    }

    public List<AuditEvent> events() {
        return List.copyOf(events);
    }
}
