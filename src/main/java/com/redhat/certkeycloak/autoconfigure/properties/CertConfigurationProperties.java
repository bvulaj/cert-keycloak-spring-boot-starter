/**
 * 
 */
package com.redhat.certkeycloak.autoconfigure.properties;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * @author bvulaj
 *
 */
@Component
@ConfigurationProperties("ssl.certs")
public class CertConfigurationProperties {

  private NoToken noToken;

  public NoToken getNoToken() {
    return noToken;
  }

  public void setNoToken(NoToken noToken) {
    this.noToken = noToken;
  }

  public static class NoToken {
    private List<String> read;
    private List<String> readWrite;

    public List<String> getRead() {
      return read;
    }

    public void setRead(List<String> read) {
      this.read = read;
    }

    public List<String> getReadWrite() {
      return readWrite;
    }

    public void setReadWrite(List<String> readWrite) {
      this.readWrite = readWrite;
    }
  }
}
