package org.primeframework.security.shiro;

import org.apache.shiro.authc.AuthenticationToken;

import org.primeframework.security.DefaultPrimeAuthenticationToken;

/**
 * @author James Humphrey
 */
public class ShiroPrimeAuthenticationToken extends DefaultPrimeAuthenticationToken implements AuthenticationToken {

  public ShiroPrimeAuthenticationToken() {
  }

  public ShiroPrimeAuthenticationToken(String username, String password) {
    super(username, password);
  }

  @Override
  public Object getPrincipal() {
    return username;
  }

  @Override
  public Object getCredentials() {
    return password;
  }
}
