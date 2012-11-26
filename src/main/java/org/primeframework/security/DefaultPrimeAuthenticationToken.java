/*
 * Copyright (c) 2012, Inversoft Inc., All Rights Reserved
 */
package org.primeframework.security;

/**
 * Simple authentication token that uses a username and password for authentication
 *
 * @author James Humphrey
 */
public class DefaultPrimeAuthenticationToken implements PrimeAuthenticationToken {
  public String username;
  public String password;

  public DefaultPrimeAuthenticationToken() {
  }

  public DefaultPrimeAuthenticationToken(String username, String password) {
    this.username = username;
    this.password = password;
  }

  public String getUsername() {
    return username;
  }

  public String getPassword() {
    return password;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public void setPassword(String password) {
    this.password = password;
  }
}
