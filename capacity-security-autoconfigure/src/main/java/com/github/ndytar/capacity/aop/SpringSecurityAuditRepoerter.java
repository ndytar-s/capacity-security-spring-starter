package com.github.ndytar.capacity.aop;

import com.github.ndytar.capacity.services.SecurityAuditReporter;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

@Component
public class SpringSecurityAuditRepoerter implements SecurityAuditReporter {

    private final ApplicationEventPublisher publisher;

    public SpringSecurityAuditRepoerter(ApplicationEventPublisher publisher) {
        this.publisher = publisher;
    }

    @Override
    public void report(SecurityAuditEvent event) {
        this.publisher.publishEvent(event);
    }
}
