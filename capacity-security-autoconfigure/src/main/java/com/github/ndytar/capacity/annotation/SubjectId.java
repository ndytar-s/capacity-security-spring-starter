package com.github.ndytar.capacity.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marque un paramètre Long qui reçoit l'identifiant du sujet porté par la
 * capacité personnelle, jamais une valeur choisie par le client ou par le LLM.
 *
 * - REST : injecté par SubjectIdArgumentResolver.
 * - Agent : injecté par CapacityAwareToolCallback, qui écrase toute valeur proposée.
 *
 * Une méthode qui porte @SubjectId n'accepte que des capacités personnelles.
 * Une capacité personnelle n'ouvre que des méthodes qui portent @SubjectId.
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
public @interface SubjectId {
}
