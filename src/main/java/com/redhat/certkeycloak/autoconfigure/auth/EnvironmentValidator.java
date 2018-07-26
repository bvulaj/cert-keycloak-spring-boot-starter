package com.redhat.certkeycloak.autoconfigure.auth;

import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;

import com.redhat.certkeycloak.autoconfigure.properties.LdapConfigurationProperties;

@Component
public class EnvironmentValidator {
  private static final Logger log = LoggerFactory.getLogger(EnvironmentValidator.class);

  private LdapConfigurationProperties ldapConfigProps;

  public static final String ENVIRONMENT_SEPARATOR = ",";

  @Autowired
  public EnvironmentValidator(LdapConfigurationProperties ldapConfigProps) {
    this.ldapConfigProps = ldapConfigProps;
    log.info("EnvironmentValidator created with environments: {} and allAccessOu: {}", getEnvironments(), getAllAccessOu());
  }

  public List<String> getEnvironments() {
    return ldapConfigProps.getEnvironments();
  }
  public String getAllAccessOu() {
    return ldapConfigProps.getAllAccessOu();
  }

  public void validate(X500Name certificateSubject) {
    if (getEnvironments().isEmpty()) {
      log.debug("No environment configured. Skipping Environment Cert verification.");
      return;
    }

    String certificateOu = CertUtils.getCertificateOU(certificateSubject);
    if(StringUtils.isBlank(certificateOu)) {
      throw new BadCredentialsException("No ou in dn, you may need to update your certificate: " + certificateSubject);
    } else {
      if (getAllAccessOu() != null && getAllAccessOu().equalsIgnoreCase(StringUtils.replace(certificateOu, " ", ""))) {
        log.debug("Skipping environment validation, user ou matches {} ", getAllAccessOu());
      } else {
        verifyDnContainsEnvironment(certificateSubject);
        if (hasLocationAttribute(certificateSubject)) {
          validateEnvironmentUsingLocationAttribute(certificateSubject);
        } else {
          validateEnvironmentUsingUidAttribute(certificateSubject);
        }
      }
    }
  }

  private void validateEnvironmentUsingUidAttribute(X500Name certificateSubject) {
    String certificateUid = CertUtils.getCertificateUid(certificateSubject);
    if(!hasEnvironmentInUid(certificateUid)) {
      handleMissingLocation(certificateSubject);
    } else if (!uidContainsEnvironment(certificateUid)){
      handleInvalidLocation(certificateUid);
    }
  }

  private void validateEnvironmentUsingLocationAttribute(X500Name certificateSubject) {
    String certificateLocation = CertUtils.getCertificateLocation(certificateSubject);
    if(StringUtils.isBlank(certificateLocation)) {
      handleMissingLocation(certificateSubject);
    } else if (!locationAttributeMatchesEnvironment(certificateLocation)) {
      handleInvalidLocation(certificateLocation);
    }
  }

  private void verifyDnContainsEnvironment(X500Name certificateSubject) {
    if(StringUtils.isBlank(CertUtils.getCertificateLocation(certificateSubject)) &&
        !uidContainsEnvironment(CertUtils.getCertificateUid(certificateSubject))) {
      throw new BadCredentialsException("No location in dn, expected one of [" + getEnvironments() + "] ,you may need to update your certificate: " + certificateSubject);
    }
  }

  private boolean hasLocationAttribute(X500Name certificateSubject) {
    return (StringUtils.isNotBlank(CertUtils.getCertificateLocation(certificateSubject))) ? true : false;
  }

  private boolean hasEnvironmentInUid(String uid) {
    return getEnvironments().stream().parallel().anyMatch(uid::contains);
  }

  private void handleMissingLocation(X500Name certificateSubject) {
    throw new BadCredentialsException("No location in dn, expected one of [" + getEnvironments() + "] ,you may need to update your certificate: " + certificateSubject);
  }

  private void handleInvalidLocation(String location) {
    throw new BadCredentialsException("Invalid location from dn, expected one of [" + getEnvironments() + "] but found " + location);
  }

  public boolean uidContainsEnvironment(String uid) {
    List<String> environments = getEnvironments();
    for(String environment : environments) {
      if(uid.contains(environment)) {
        return true;
      }
    }
    return false;
  }

  public boolean locationAttributeMatchesEnvironment(String location) {
    List<String> environments = getEnvironments();
    for(String environment : environments) {
      if(environment.equalsIgnoreCase(location)) {
        return true;
      }
    }
    return false;
  }

}
