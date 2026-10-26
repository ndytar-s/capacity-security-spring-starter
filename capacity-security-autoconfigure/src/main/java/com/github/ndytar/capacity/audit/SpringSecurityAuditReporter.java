package com.github.ndytar.capacity.audit;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

import java.util.List;

@Slf4j
public class SpringSecurityAuditReporter
        implements SecurityAuditReporter {

    private final ApplicationEventPublisher publisher;

    public SpringSecurityAuditReporter(ApplicationEventPublisher publisher) {

        this.publisher = publisher;
    }

    @Override
    public void report(List<AuditEvent> events) {

        if (events == null || events.isEmpty()) {
            return;
        }
        publisher.publishEvent(new SecurityAuditEvent(List.copyOf(events)));
    }
}
