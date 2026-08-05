package com.github.ndytar.capacity.aop;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;

@Aspect
@Slf4j
public class SecurityAuditAspect {

    @AfterReturning(
            pointcut = "execution(* ..SecurityAuditReporter.report(..)) && args(event)"
    )
    public void audit(SecurityAuditEvent event) {

        log.info("""
        ========= SECURITY AUDIT =========
        Type      : {}
        User      : {}
        Resource  : {}
        Evenment  : {}
        Actions    : {}
        Time      : {}
        ================================
        """,
                event.AuditType(),
                event.username(),
                event.resource(),
                event.evenement(),
                event.actionsList(),
                event.timestamp());

    }
}
