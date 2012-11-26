/*
 * Copyright (c) 2012, Inversoft Inc., All Rights Reserved
 */
package org.primeframework.security;

/**
 * Login token interface that requires username and password
 *
 * @author James Humphrey
 */
public interface PrimeAuthenticationToken {

  /**
   * Return the username
   *
   * @return the username
   */
  public String getUsername();

  /**
   * Return the password
   *
   * @return the password
   */
  public String getPassword();
}
