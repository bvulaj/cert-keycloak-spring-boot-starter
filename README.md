Autoconfiguration for common SSL / Cert Auth w/ Keycloak JWT services and rules


An example `SecurityConfiguration`

``` java
@Configuration
@EnableWebSecurity
@ComponentScan(basePackageClasses = KeycloakSecurityComponents.class)
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration extends KeycloakWebSecurityConfigurerAdapter {
    @Bean
    public KeycloakSpringBootConfigResolver KeycloakConfigResolver() {
        return new KeycloakSpringBootConfigResolver();
    }
    
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(new KeycloakAuthenticationProvider());
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception
    { 
        super.configure(httpSecurity);
        httpSecurity
          .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // OIDC & Keycloak use stateless authentication
          .and()
            .csrf().disable()
          .authorizeRequests()
            .antMatchers("/**/createUser")
              .access(CertKeycloakAccessRules.inAuthorizedGroup())
            .antMatchers("/**/find**")
              .access(CertKeycloakAccessRules.allowReadAccess())
            .antMatchers("/**/update**", "/**/create**")
              .access(CertKeycloakAccessRules.allowReadWriteAccess());
    }

    @Override
    @Bean
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
      return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }
}

```

An example `application.properties`

```
# CSV of CNs allowed access without an OIDC token
ssl.certs.no-token.read=client-no-token
ssl.certs.no-token.read-write=admin-client-no-token

# LDAP CONFIG
ldap.server=ldap.myhost.com
ldap.port=636
ldap.bindDn=uid=my-uid,ou=accounts,dc=foobar,dc=com
ldap.bindDNPwd=pwd
ldap.poolSize=5
ldap.useSSL=true
ldap.debug=false
ldap.trustStorePassword=password
ldap.connectionTimeoutMS=30000
ldap.responseTimeoutMS=30000
ldap.keepAlive=true
ldap.poolMaxConnectionAgeMS=15000
ldap.user-details.search_base=dc=redhat,dc=com
ldap.user-details.rolesCacheExpiryMS=300000
ldap.environment=dev,qa,stage
ldap.allAccessOu=users
ldap.authz-user-group=my-service-group

# SSL Keystore
server.ssl.key-store-type=JKS
server.ssl.key-store=classpath:keystore.jks
server.ssl.key-store-password=password
server.ssl.key-store-provider=SUN

# SSL Truststore
server.ssl.trust-store-type=JKS
server.ssl.trust-store=classpath:truststore.jks
server.ssl.trust-store-password=password
server.ssl.trust-store-provider=SUN

server.ssl.client-auth=want

# Keycloak
keycloak.auth-server-url=https://sso.myhost.com/auth
keycloak.realm=myorg-external
keycloak.resource=myservice
keycloak.credentials.secret=my-secret
keycloak.bearer-only=true
keycloak.principal-attribute=preferred_username
keycloak.truststore=${server.ssl.trust-store}
keycloak.truststore-password=${server.ssl.trust-store-password}
```

Example test using `WithMockKeycloakUser`

```
@RunWith(SpringRunner.class)
@SpringBootTest(
    properties = { "ssl.certs.no-token.read-write=test-read-cert", "ssl.certs.no-token.read=test-rest-write-cert" }
)
@AutoConfigureMockMvc
public class SecurityIntegrationTest {

  @Autowired
  private MockMvc mockMvc;
  
  @Test
  @WithMockKeycloakUser
  public void withCertAndTokenShouldBeAllowed() throws Exception {
    mockMvc.perform(
        post("/findUser")
          .with(x509("cert-that-requires-jwt.pem"))
          .contentType(MediaType.APPLICATION_JSON)
          .content(...)
        .andExpect(status().isOk());
  }
  
  @Test
  public void withCertAndNoTokenShouldBeDisallowed() throws Exception {
    mockMvc.perform(
        post("/findUser")
          .with(x509("cert-that-requires-jwt.pem"))
          .contentType(MediaType.APPLICATION_JSON)
          .content(...)
        .andExpect(status().isUnauthorized());
  }
}
```