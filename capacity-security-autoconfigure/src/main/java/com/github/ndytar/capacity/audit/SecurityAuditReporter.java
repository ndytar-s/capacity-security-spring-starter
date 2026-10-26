package com.github.ndytar.capacity.audit;

import java.util.List;

public interface SecurityAuditReporter {

    void report(List<AuditEvent> events);

}
