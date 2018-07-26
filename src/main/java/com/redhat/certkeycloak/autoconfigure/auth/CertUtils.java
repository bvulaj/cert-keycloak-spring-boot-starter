/**
 * 
 */
package com.redhat.certkeycloak.autoconfigure.auth;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.ArrayUtils;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;

/**
 * @author bvulaj
 *
 */
public abstract class CertUtils {
  private static final Logger log = LoggerFactory.getLogger(CertUtils.class);
  
  public static X509Certificate getCertificateFromRequest(HttpServletRequest request) {
    X509Certificate[] certChain = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
    X509Certificate cert = null;
    if (certChain != null) {
      if (certChain.length > 0) {
        /// Taking the first one in the chain, which should be client cert
        cert = certChain[0];
      }
    }
    return cert;
  }

  public static X500Name getCertificateSubject(X509Certificate certificate) {
    if (certificate == null) {
      throw new BadCredentialsException("A client certificate is required for this request");
    } else {
      try {
        return new JcaX509CertificateHolder(certificate).getSubject();
      } catch (CertificateEncodingException cee) {
        throw new BadCredentialsException("Unable to parse client certificate ", cee);
      }
    }
  }

  public static String getCertificateUid(X500Name certificateSubject) {
    RDN[] uids = certificateSubject.getRDNs(BCStyle.UID);
    if (ArrayUtils.isEmpty(uids)) {
      throw new BadCredentialsException("A UID attribute could not be found in the certificate subject: " + certificateSubject.toString());
    }

    String certificateUID = IETFUtils.valueToString(uids[0].getFirst().getValue());
    log.debug("Client certificate UID: {}", certificateUID);
    return certificateUID;
  }

  public static String getCertificateOU(X500Name certificateSubject) {
    RDN[] ous = certificateSubject.getRDNs(BCStyle.OU);
    if (ArrayUtils.isEmpty(ous)) {
      throw new BadCredentialsException("A OU attribute could not be found in the certificate subject: " + certificateSubject.toString());
    }

    String organizationalUnit = IETFUtils.valueToString(ous[0].getFirst().getValue());
    log.debug("Client certificate OU: {}", organizationalUnit);
    return organizationalUnit;
  }

  public static String getCertificateLocation(X500Name certificateSubject) {
    RDN[] locations = certificateSubject.getRDNs(BCStyle.L);
    if (ArrayUtils.isEmpty(locations)) {
      log.debug("No L attibute in certificate subject: {}", certificateSubject.toString());
      return new String();
    }

    String location = IETFUtils.valueToString(locations[0].getFirst().getValue());
    log.debug("Client certificate L: {}", location);
    return location;
  }
}
