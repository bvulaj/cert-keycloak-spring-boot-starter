/**
 * 
 */
package com.redhat.certkeycloak.autoconfigure.auth;

import javax.servlet.http.HttpServletRequest;

import org.esbtools.auth.spring.LdapUserDetailsService;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.redhat.certkeycloak.autoconfigure.properties.CertConfigurationProperties;
import com.redhat.certkeycloak.autoconfigure.properties.LdapConfigurationProperties;

/**
 * @author bvulaj
 *
 */
@Component
public class AuthenticationHandler {

  private static final Logger log = LoggerFactory.getLogger(AuthenticationHandler.class);

  @Autowired
  private LdapConfigurationProperties ldapConfigProps;
  @Autowired
  private CertConfigurationProperties certConfigProps;
  @Autowired
  public LdapUserDetailsService ldapUserDetailsService;
  
  /**
   * 
   * @param authentication
   * @param request
   * @return True if a valid cert and JWT are provided. True if only a valid cert with read-only non-JWT access is provided. False otherwise.
   */
  public boolean allowReadAccess(Authentication authentication, HttpServletRequest request) {
    if (isTokenAuthenticated(authentication, request)) { // the request contains a valid cert
      return true;
    }
    return isReadNoTokenRequiredCertPresent(request) || isReadWriteNoTokenRequiredCertPresent(request);
  }
  
  /**
   * 
   * @param authentication
   * @param request
   * @return True if a valid cert and JWT are provided. True if only a valid cert with read-write non-JWT access is provided. False otherwise.
   */
  public boolean allowReadWriteAccess(Authentication authentication, HttpServletRequest request) {
    if (isTokenAuthenticated(authentication, request)) { // the request contains a valid cert
      return true;
    }
    return isReadWriteNoTokenRequiredCertPresent(request);
  }
  
  /**
   * 
   * @param request
   * @return True if the provided cert is in the approved authorized group in ldap
   */
  public boolean isInAuthorizedUsersGroup(HttpServletRequest request) {
    String certificateUid = CertUtils.getCertificateUid(CertUtils.getCertificateSubject(CertUtils.getCertificateFromRequest(request)));
    if(!isInAuthorizedUsersGroup(certificateUid)) {
      log.info("Access for {} is not allowed if not a member of {} group", certificateUid, ldapConfigProps.getAuthzUserGroup());
      return false;
    }
    return true;
  }

  private boolean isTokenAuthenticated(Authentication authentication, HttpServletRequest request) {
    if (!isInAuthorizedUsersGroup(request)) {
      // check if the request contains a valid cert via ldap grant
      return false;
    }
    // check if the request contains a valid OIDC token
    return (authentication.isAuthenticated() && authentication instanceof KeycloakAuthenticationToken);
  }
  
  /**
   * Some certificates do not require a JWT token and their auth is handled differently, this helper method identifies those special certs
   * @param request the request object which contains the certificate
   * @return true if the certificate supplied by the user matches a list of pre-defined certificates which do not require jwt tokens for auth
   */
  private boolean isReadNoTokenRequiredCertPresent(HttpServletRequest request) {
    String certificateCN = CertUtils.getCertificateUid(CertUtils.getCertificateSubject(CertUtils.getCertificateFromRequest(request)));
    log.debug("Verifying non-JWT access for {} for URI {}", certificateCN, request.getRequestURI());
    if (certConfigProps.getNoToken().getRead().contains(certificateCN)) {
      return true;
    }
    log.info("Access for {} is not allowed without a JWT", certificateCN);
    return false;
  }
  
  private boolean isReadWriteNoTokenRequiredCertPresent(HttpServletRequest request) {
    String certificateCN = CertUtils.getCertificateUid(CertUtils.getCertificateSubject(CertUtils.getCertificateFromRequest(request)));
    log.debug("Verifying non-JWT access for {} for URI {}", certificateCN, request.getRequestURI());
    if (certConfigProps.getNoToken().getReadWrite().contains(certificateCN)) {
      return true;
    }
    log.info("Access for {} is not allowed without a JWT", certificateCN);
    return false;
  }

  private boolean isInAuthorizedUsersGroup(String certificateUid) {
    if(ldapConfigProps.getAuthzUserGroup() != null) {
      UserDetails userDetails = ldapUserDetailsService.loadUserByUsername(certificateUid);
      SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority(ldapConfigProps.getAuthzUserGroup());
      return userDetails.getAuthorities().contains(simpleGrantedAuthority);
    } else {
      return true;
    }
  }

 

}
