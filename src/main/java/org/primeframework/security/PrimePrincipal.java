package org.primeframework.security;

import java.security.Principal;

/**
 * Marker interface.  No additional API on top of Principal at the moment, but reserving the right for later
 *
 * @author James Humphrey
 */
public interface PrimePrincipal extends Principal {

  /**
   * Returns true if the primary principal exists.  In other words, if, for instance, the principal username
   * supplied doesn't match any username in the system (i.e. ldap, active directory, database, etc) then
   * defined should return false.  Undefined principals will cause
   *
   * @return true or false
   */
  boolean isDefined();

  /**
   * The Subject's hashed credentials
   *
   * @return the hashed credentials
   */
  String hashedCredentials();
}