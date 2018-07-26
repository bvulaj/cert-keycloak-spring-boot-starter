/**
 * 
 */
package com.redhat.certkeycloak.autoconfigure.test;

import java.security.Principal;
import java.util.Collections;
import java.util.Set;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.OidcKeycloakAccount;
import org.keycloak.adapters.spi.KeycloakAccount;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

/**
 * @author bvulaj
 *
 */
public class MockKeycloakSecurityContext implements WithSecurityContextFactory<WithMockKeycloakUser> {

  @Override
  public SecurityContext createSecurityContext(WithMockKeycloakUser user) {
    SecurityContext context = SecurityContextHolder.getContext();
    KeycloakAccount account = new OidcKeycloakAccount() {

      @Override
      public Set<String> getRoles() {
        return Collections.emptySet();
      }

      @Override
      public Principal getPrincipal() {
        return new KeycloakPrincipal<KeycloakSecurityContext>(user.username(), getKeycloakSecurityContext());
      }

      @Override
      public KeycloakSecurityContext getKeycloakSecurityContext() {
        return new KeycloakSecurityContext();
      }
    };
    KeycloakAuthenticationToken token = new KeycloakAuthenticationToken(account, false, AuthorityUtils.createAuthorityList());

    context.setAuthentication(token);
    return context;
  }

}
