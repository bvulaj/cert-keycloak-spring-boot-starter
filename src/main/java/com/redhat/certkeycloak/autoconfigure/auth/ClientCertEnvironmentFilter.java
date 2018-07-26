/**
 * 
 */
package com.redhat.certkeycloak.autoconfigure.auth;

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;

/**
 * Verifies that the provided certificate, if it exists, is for the correct environment. It will also add the certificate name to the cert-name header.
 * 
 * @author bvulaj, dhaynes
 *
 */
@Component
public class ClientCertEnvironmentFilter implements Filter {

  private static final Logger log = LoggerFactory.getLogger(ClientCertEnvironmentFilter.class);
  private EnvironmentValidator environmentValidator;

  public ClientCertEnvironmentFilter(EnvironmentValidator environmentValidator) {
    this.environmentValidator = environmentValidator;
    log.info("ClientCertEnvironmentFilter created with environments: {} and allAccessOu: {}", environmentValidator.getEnvironments(), environmentValidator.getAllAccessOu());
  }

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    log.info("Registering ClientCertEnvironmentFilter");
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest req = (HttpServletRequest) request;
    HttpServletResponse resp = (HttpServletResponse) response;
    X509Certificate cert = CertUtils.getCertificateFromRequest(req);
    if (cert != null) { // only try to validate if there is a cert
      try {
        X500Name certificateSubject = CertUtils.getCertificateSubject(cert);
        resp.addHeader("cert-name", CertUtils.getCertificateUid(certificateSubject));
        environmentValidator.validate(certificateSubject);
      } catch (BadCredentialsException e) {
        log.error("Client certificate environment verification failed: {}", e);
        resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        return;
      }
    }
    chain.doFilter(req, resp);
  }

  @Override
  public void destroy() {
    log.info("Unregistering ClientCertEnvironmentFilter");
  }
}
