/*
 * Copyright (c) 2012, Inversoft Inc., All Rights Reserved
 */
package org.primeframework.security;

import org.joda.time.DateTime;

/**
 * Implement to listen for logout and login events
 *
 * @author James Humphrey
 */
public interface AuthenticationListener<T extends PrimePrincipal> {

  /**
   * Called on logout
   *
   * @param principal     the principal
   * @param logoutInstant the logout instant
   */
  public void onLogout(T principal, DateTime logoutInstant);

  /**
   * Called on login
   *
   * @param principal the principal
   */
  public void onLogin(T principal);
}
