/*
 * Copyright (c) 2012, Inversoft Inc., All Rights Reserved
 */
package org.primeframework.security;

/**
 * Interface for interacting with the security framework
 *
 * @author James Humphrey
 */
public interface SecurityService<T extends PrimePrincipal> {


  /**
   * Log in using the login info.  if the primary security principal is already set, then this implementation assumes
   * the user is already logged in and passed it along to the underlying security framework
   *
   * @param primeAuthenticationToken the authentication info
   */
  void login(PrimeAuthenticationToken primeAuthenticationToken);

  /**
   * Logout
   */
  void logout();

  /**
   * True if logged in, false otherwise
   *
   * @return true or false
   */
  boolean isLoggedIn();

  /**
   * Returns the principals associated to the currently authenticated user.  Principals are any information that
   * uniquely identifies an account in your system
   */
  T getPrincipal();

  /**
   * Encrypts a password
   *
   * @param encryptionAlgorithm      the encryption algorithm
   * @param password       the password to encrypt
   * @param salt           the salt to use for encryption
   * @param hashIterations the number of times to encrypt it
   * @param encodingType   the encoding type
   * @return the encrypted password
   */
  public String encryptPassword(EncryptionAlgorithm encryptionAlgorithm, String password, Object salt, int hashIterations,
                                EncodingType encodingType);

  /**
   * The encoding for password encryption
   */
  public static enum EncodingType {
    BASE64,
    HEX
  }

  public static enum EncryptionAlgorithm {
    SHA_256("SHA-256"),
    MD5("MD5");

    public String encryptionAlgorithm;

    EncryptionAlgorithm(String encryptionAlgorithm) {
      this.encryptionAlgorithm = encryptionAlgorithm;
    }
  }
}
