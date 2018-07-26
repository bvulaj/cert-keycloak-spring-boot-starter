/**
 * 
 */
package com.redhat.certkeycloak.autoconfigure.properties;

import java.util.List;

import org.esbtools.auth.ldap.LdapConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;

/**
 * @author bvulaj
 *
 */
@Component
@ConfigurationProperties("ldap")
public class LdapConfigurationProperties extends LdapConfiguration {

  private UserDetails userDetails;
  private String authzUserGroup;
  @Nullable
  private List<String> environments;
  @Nullable
  private String allAccessOu;

  public List<String> getEnvironments() {
    return environments;
  }

  public void setEnvironments(List<String> environments) {
    this.environments = environments;
  }

  public String getAllAccessOu() {
    return allAccessOu;
  }

  public void setAllAccessOu(String allAccessOu) {
    this.allAccessOu = allAccessOu;
  }

  public UserDetails getUserDetails() {
    return userDetails;
  }

  public void setUserDetails(UserDetails userDetails) {
    this.userDetails = userDetails;
  }

  public String getAuthzUserGroup() {
    return authzUserGroup;
  }

  public void setAuthzUserGroup(String authzUserGroup) {
    this.authzUserGroup = authzUserGroup;
  }

  public static class UserDetails {
    private String searchBase;
    private Integer rolesCacheExpiryMS;

    public String getSearchBase() {
      return searchBase;
    }

    public void setSearchBase(String searchBase) {
      this.searchBase = searchBase;
    }

    public Integer getRolesCacheExpiryMS() {
      return rolesCacheExpiryMS;
    }

    public void setRolesCacheExpiryMS(Integer rolesCacheExpiryMS) {
      this.rolesCacheExpiryMS = rolesCacheExpiryMS;
    }

  }
}
