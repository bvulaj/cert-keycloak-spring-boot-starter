package com.redhat.certkeycloak.autoconfigure;

import org.esbtools.auth.spring.LdapUserDetailsService;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import com.redhat.certkeycloak.autoconfigure.properties.LdapConfigurationProperties;

/**
 * Register expected utilities and services for SSL / Cert Auth + Keycloak OIDC when a KeycloakWebSecurityConfigurerAdapter is detected
 * 
 * @author bvulaj
 *
 */
@Configuration
@ComponentScan
@ConditionalOnBean(KeycloakWebSecurityConfigurerAdapter.class)
public class CertKeycloakAutoconfiguration {

  @Bean
  @ConditionalOnMissingBean
  public LdapUserDetailsService ldapUserDetailsService(LdapConfigurationProperties ldapConfigurationProperties) throws Exception {
    return new LdapUserDetailsService(
        ldapConfigurationProperties.getUserDetails().getSearchBase(),
        ldapConfigurationProperties,
        ldapConfigurationProperties.getUserDetails().getRolesCacheExpiryMS());
  }
}
