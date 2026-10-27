package com.github.ndytar.capacity.config;

import com.github.ndytar.capacity.audit.AuditEvent;
import com.github.ndytar.capacity.audit.DefaultAuditEventHandler;
import com.github.ndytar.capacity.audit.LogAuditSystem;
import com.github.ndytar.capacity.properties.CapacitySecurityPropertie;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;

import java.util.List;

@Slf4j
@AutoConfiguration
public class DefaultLogAuditSystem
        implements LogAuditSystem {
  private  final CapacitySecurityPropertie properties;

    public DefaultLogAuditSystem(CapacitySecurityPropertie properties) {
        this.properties = properties;
    }

    @ConditionalOnMissingBean({LogAuditSystem.class})
    @Override
    public void log(List<AuditEvent> events) {
       if (properties.isLogAudit())
           for (AuditEvent event : events) {

            log.info(
                    "\n===============AUDIT===========\n | time={}\n | action={}\n | resource={}\n | subject={}\n | result={}\n | reason={}\n",
                    event.timestamp(),
                    event.action(),
                    event.resource(),
                    event.subject(),
                    event.result(),
                    event.reason()
            );
        }
    }
}
