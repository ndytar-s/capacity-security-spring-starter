package com.github.ndytar.capacity.services;

import  com.github.ndytar.capacity.aop.SecurityAuditEvent;

public interface SecurityAuditReporter {
    void report(SecurityAuditEvent event);
}
