package com.github.ndytar.capacity.audit;

import java.util.List;

public interface LogAuditSystem {
    void  log(List<AuditEvent> event);
}
