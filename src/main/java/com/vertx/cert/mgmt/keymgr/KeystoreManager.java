package com.vertx.cert.mgmt.keymgr;

import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Enumeration;
import java.util.stream.Collectors;

public class KeystoreManager {

  private static final char[] KEYSTORE_PASSWORD = "abc".toCharArray();
  private KeyStore mKeyStore = null;

  public KeystoreManager() {
    if( mKeyStore == null) {
      this.mKeyStore = createStore();
    }
  }

  public KeyStore getKeyStore() {
    return mKeyStore;
  }

  public char[] getKeystorePassword() {
    return KEYSTORE_PASSWORD;
  }

  public KeyStore createStore() {
 //   KeyStore keyStore = null;
    try {
      mKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      mKeyStore.load(null, KEYSTORE_PASSWORD);

      //loadServerCertificate(CertKeyConstants.testCertStr, CertKeyConstants.testKeyStr);
      reloadServerCertificate("certs/bazcert.der", "keys/bazKey.der");


    } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
      throw new RuntimeException("Unable to create empty keyStore", e);
    }

    return mKeyStore;
  }

  public void reloadServerCertificate(String certFilename, String keyFilename) {
    try {
      clearKeyStore();

      //load key
      InputStream keyInputStream = fullStream(keyFilename);
      byte[] key  = new byte[keyInputStream.available()];
      keyInputStream.read(key, 0, keyInputStream.available());
      keyInputStream.close();

      //load certificate
      InputStream certStream = fullStream(certFilename);
      //byte[] cert = new byte[certStream.available()];
      //certStream.read(cert, 0, certStream.available());
      //certStream.close();

      loadServerCertificate(certStream, key);
      certStream.close();
    } catch(Exception ex) {
      System.out.println("Error while reloading the certificate :" + ex.getLocalizedMessage());
    }
  }

  /*public void loadServerCertificate(String certStr, String keyStr) {
    try {

      Certificate[] certs = getCertificateChain(certStr);
      PrivateKey pKey = getPrivateKey(keyStr);
      mKeyStore.setKeyEntry("test", pKey, KEYSTORE_PASSWORD, certs);

    } catch (Exception ex) {
      System.out.println("Error while adding the server certificate!!!" + ex.getLocalizedMessage());
    }
  }*/

  public void loadServerCertificate(InputStream certstream, byte[] keyStr) {
    try {

      Certificate[] certs = getCertificateChain(certstream);
      PrivateKey pKey = getPrivateKey(keyStr);
      mKeyStore.setKeyEntry("test", pKey, KEYSTORE_PASSWORD, certs);

    } catch (Exception ex) {
      System.out.println("Error while adding the server certificate!!!" + ex.getLocalizedMessage());
    }
  }

  public synchronized KeyManager[] getKeyManagers()
      throws GeneralSecurityException {
    if (mKeyStore == null) {
      throw new NullPointerException("null mKeyStore");
    }

    KeyManagerFactory factory =
        KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    factory.init(mKeyStore, KEYSTORE_PASSWORD);
    return factory.getKeyManagers();
  }

  private static String removeHeaderFooterAndLineBreakFromPEM(String pem) {
    String[] strArr = pem.split("\\r?\\n");
    return Arrays.stream(strArr)
        .limit(strArr.length - 1)
        .skip(1)
        .collect(Collectors.joining());
  }

  private Certificate[] getCertificateChain(InputStream certstream) {
    Certificate[] certs = null;

    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      Collection c = cf.generateCertificates(certstream) ;
      certs = new Certificate[c.toArray().length];

      if (c.size() == 1) {
        certstream = fullStream ("certs/bazcert.der");
        System.out.println("One certificate, no chain.");
        Certificate cert = cf.generateCertificate(certstream) ;
        certs[0] = cert;
      } else {
        System.out.println("Certificate chain length: "+c.size());
        certs = (Certificate[])c.toArray();
      }
    } catch (Exception ex) {
    }

    return certs;
  }


  /*private Certificate[] getCertificateChain(String certStr) {
    Certificate[] certs = new Certificate[2];

    try {
      byte[] certByteArr = certStr.getBytes(StandardCharsets.UTF_8);
      InputStream is = new ByteArrayInputStream(certByteArr);
      InputStream bis = new BufferedInputStream(is);
      CertificateFactory fact = CertificateFactory.getInstance("X.509");
      java.security.cert.X509Certificate cert =
          (java.security.cert.X509Certificate) fact.generateCertificate(bis);
      certs[0] = cert;
    } catch (Exception ex) {
    }

    return certs;
  }*/

  /*private PrivateKey getPrivateKey(String keyStr) throws Exception {
    KeyFactory kf = KeyFactory.getInstance("RSA");
    String normalizedKeyStr = removeHeaderFooterAndLineBreakFromPEM(keyStr);
    byte[] priKeyArr = Base64.getDecoder().decode(normalizedKeyStr);
    DerInputStream dis = new DerInputStream(priKeyArr);
    DerValue[] seq = dis.getSequence(0);
    BigInteger mod = seq[1].getBigInteger();
    BigInteger privExpo = seq[3].getBigInteger();

    RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(mod, privExpo);
    return kf.generatePrivate(keySpec);
  }*/

  private PrivateKey getPrivateKey(byte[] keyStr) throws Exception {
    KeyFactory kf = KeyFactory.getInstance("RSA");
    PKCS8EncodedKeySpec keysp = new PKCS8EncodedKeySpec( keyStr );

    return kf.generatePrivate(keysp);
  }

  private void clearKeyStore() {
    try {
      for (Enumeration<String> e = mKeyStore.aliases();
           e.hasMoreElements(); ) {
        final String alias = e.nextElement();
        mKeyStore.deleteEntry(alias);
      }
    } catch (KeyStoreException e) {
    }
  }

  private static InputStream fullStream(String fname) throws IOException {
    ClassLoader classLoader = ClassLoader.getSystemClassLoader();
    File file = new File(classLoader.getResource(fname).getFile());

    FileInputStream fis = null;
    DataInputStream dis = null;
    try {
      fis = new FileInputStream(file);
      dis = new DataInputStream(fis);
      byte[] bytes = new byte[dis.available()];
      dis.readFully(bytes);
      ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
      return bais;
    } finally {
      fis.close();
      dis.close();
    }
  }
}
