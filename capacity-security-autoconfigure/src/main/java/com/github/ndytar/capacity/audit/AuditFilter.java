package com.github.ndytar.capacity.audit;

import com.github.ndytar.capacity.customclaims.CustomClaimsContextHolder;
import com.github.ndytar.capacity.proof.Actions;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
@Slf4j


public class AuditFilter extends OncePerRequestFilter {

    private final SecurityAuditReporter reporter;

    public AuditFilter(SecurityAuditReporter reporter) {
        this.reporter = reporter;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

       AuditContext context = new AuditContext();

        AuditContextHolder.set(context);

        try {

            filterChain.doFilter(request, response);

        } finally {

            try {
                reporter.report(context.events());

            } finally {
                AuditContextHolder.clear();
                Actions.get.actions().clear();
                CustomClaimsContextHolder.clear();
            }
        }
    }
}
