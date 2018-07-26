package com.redhat.certkeycloak.autoconfigure.test;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import org.springframework.security.test.context.support.WithSecurityContext;

@Retention(RetentionPolicy.RUNTIME)
@WithSecurityContext(factory = MockKeycloakSecurityContext.class)
public @interface WithMockKeycloakUser {
	String username() default "test-user";
}