package com.github.ndytar.capacity.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface AllowedIp {
    // Permet d'écrire @AllowedIp("192.168.1.5")
    String value() ;
}
