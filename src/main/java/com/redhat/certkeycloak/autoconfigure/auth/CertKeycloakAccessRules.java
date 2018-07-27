/**
 * 
 */
package com.redhat.certkeycloak.autoconfigure.auth;

/**
 * @author bvulaj
 *
 */
public abstract class CertKeycloakAccessRules {

  /**
   * 
   * @return '@authenticationHandler.isInAuthorizedUsersGroup(request)'
   */
  public static String inAuthorizedGroup() {
    return "@authenticationHandler.isInAuthorizedUsersGroup(request)";
  }

  /**
   * 
   * @return '@authenticationHandler.allowReadAccess(authentication, request)'
   */
  public static String allowReadAccess() {
    return "@authenticationHandler.allowReadAccess(authentication, request)";
  }
  
  /**
   * 
   * @return '@authenticationHandler.allowReadAccess(authentication, request)'
   */
  public static String allowReadWriteAccess() {
    return "@authenticationHandler.allowReadWriteAccess(authentication, request)";
  }
}
