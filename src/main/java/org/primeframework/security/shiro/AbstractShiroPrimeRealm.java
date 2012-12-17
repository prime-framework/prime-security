/*
 * Copyright (c) 2012, Inversoft Inc., All Rights Reserved
 */
package org.primeframework.security.shiro;

import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.apache.shiro.util.SimpleByteSource;
import org.primeframework.security.PrimePrincipal;
import org.primeframework.security.error.UndefinedPrincipalException;

import com.google.inject.Inject;

/**
 * @author James Humphrey
 */
public abstract class AbstractShiroPrimeRealm<T extends PrimePrincipal, S extends ShiroPrimeAuthenticationToken> extends AuthorizingRealm {

  @Inject
  public AbstractShiroPrimeRealm(CredentialsMatcher credentialsMatcher) {
    this.setCredentialsMatcher(credentialsMatcher);
  }

  @Override
  public boolean supports(AuthenticationToken token) {
    return token != null && (token instanceof ShiroPrimeAuthenticationToken);
  }

  @Override
  @SuppressWarnings(value = "unchecked")
  protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {

    T principal = (T) principals.getPrimaryPrincipal();

    return new SimpleAuthorizationInfo(roles(principal));
  }

  @Override
  @SuppressWarnings(value = "unchecked")
  protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

    S primeShiroToken = (S) token;

    T principal = loadPrincipal(primeShiroToken);

    if (!principal.isDefined()) {
      throw new UndefinedPrincipalException();
    }

    byte[] salt = salt(primeShiroToken).getBytes();
    ByteSource saltByteSource = new SimpleByteSource(salt);

    return new SimpleAuthenticationInfo(principal, principal.hashedCredentials(), saltByteSource, realmName());
  }

  /**
   * returns roles for the principal provided
   *
   * @param principal the principal
   * @return the set of roles belonging to the principal
   */
  protected abstract Set<String> roles(T principal);

  /**
   * Loads the principal from the datastore (user database, ldap, active directory, etc)
   *
   * @param primeShiroToken the auth token
   * @return principal T
   */
  protected abstract T loadPrincipal(S primeShiroToken);
  /**
   * The salt used to encrypt the password
   *
   * @return the salt
   */
  protected abstract String salt(S primeShiroToken);

  /**
   * The name of the realm
   *
   * @return the realm name
   */
  protected abstract String realmName();
}
