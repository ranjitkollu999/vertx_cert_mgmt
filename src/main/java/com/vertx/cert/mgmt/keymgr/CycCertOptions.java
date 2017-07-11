package com.vertx.cert.mgmt.keymgr;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.StandardConstants;
import javax.net.ssl.X509ExtendedKeyManager;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;

import io.vertx.core.Vertx;
import io.vertx.core.net.KeyCertOptions;

public class CycCertOptions implements KeyCertOptions, Cloneable {
  private final MyKeyManager keyManager = new MyKeyManager();

  public CycCertOptions() {
    super();
  }

  public CycCertOptions(CycCertOptions other) {
    super();
  }

  public void loadKeyStore() {
    try {
      keyManager.load();
    } catch(UnrecoverableKeyException | KeyStoreException e) {

    }
  }

  @Override
  public KeyManagerFactory getKeyManagerFactory(Vertx vertx) throws Exception {
    return keyManager.getKeyManagerFactory();
  }

  @Override
  public CycCertOptions clone() {

    return new CycCertOptions(this);
  }

  static class MyKeyManager extends X509ExtendedKeyManager {
    KeystoreManager ksMgr = null;
    private volatile X509ExtendedKeyManager wrapped;
    KeyManagerFactory keyManagerFactory = null;

    public MyKeyManager() {

      try {
        ksMgr = new KeystoreManager();
        keyManagerFactory =
            KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(ksMgr.getKeyStore(), ksMgr.getKeystorePassword());
        wrapped = (X509ExtendedKeyManager) keyManagerFactory.getKeyManagers()[0];
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    }

    public void load() throws UnrecoverableKeyException, KeyStoreException {
      try {
        keyManagerFactory =
            KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(ksMgr.getKeyStore(), ksMgr.getKeystorePassword());
        wrapped = (X509ExtendedKeyManager) keyManagerFactory.getKeyManagers()[0];
      } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException(e);
      }
    }

    public KeyManagerFactory getKeyManagerFactory() {
      return keyManagerFactory;
    }

    @Override
    public String chooseEngineServerAlias(String s, Principal[] principals, SSLEngine engine) {
      ExtendedSSLSession session = (ExtendedSSLSession) engine.getHandshakeSession();

      // Pick first SNIHostName in the list of SNI names.
      String hostname = null;
      for (SNIServerName name : session.getRequestedServerNames()) {
        if (name.getType() == StandardConstants.SNI_HOST_NAME) {
          hostname = ((SNIHostName) name).getAsciiName();
          break;
        }
      }

      // If we got given a hostname over SNI, check if we have a cert and key for that hostname. If so, we use it.
      // Otherwise, we fall back to the default certificate.
      if (hostname != null && (getCertificateChain(hostname) != null && getPrivateKey(hostname) != null))
        return hostname;

      return "test";
    }

    @Override
    public String[] getServerAliases(String s, Principal[] principals) {
      throw new UnsupportedOperationException();
    }

    @Override
    public X509Certificate[] getCertificateChain(String s) {
      return wrapped == null ? null : wrapped.getCertificateChain(s);
    }

    @Override
    public PrivateKey getPrivateKey(String s) {
      return wrapped == null ? null : wrapped.getPrivateKey(s);
    }

    @Override
    public String[] getClientAliases(String s, Principal[] principals) {
      throw new UnsupportedOperationException();
    }

    @Override
    public String chooseClientAlias(String[] strings, Principal[] principals, Socket socket) {
      throw new UnsupportedOperationException();
    }

    @Override
    public String chooseServerAlias(String s, Principal[] principals, Socket socket) {
      throw new UnsupportedOperationException();
    }
  }

  static class MyKeyManagerFactory extends KeyManagerFactory {
    MyKeyManagerFactory(final KeyManager keyManager) {
      super(new KeyManagerFactorySpi() {
        @Override
        protected void engineInit(KeyStore keyStore, char[] chars) throws KeyStoreException,
            NoSuchAlgorithmException, UnrecoverableKeyException {
          throw new UnsupportedOperationException();
        }

        @Override
        protected void engineInit(ManagerFactoryParameters managerFactoryParameters) throws
            InvalidAlgorithmParameterException {
          throw new UnsupportedOperationException();
        }

        @Override
        protected KeyManager[] engineGetKeyManagers() {
          return new KeyManager[]{keyManager};
        }
      }, new Provider("", 0.0, "") {
      }, "");
    }
  }
}

