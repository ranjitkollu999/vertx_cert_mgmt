package com.vertx.cert.mgmt;

import com.vertx.cert.mgmt.keymgr.CycCertOptions;
import com.vertx.cert.mgmt.keymgr.KeystoreManager;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.net.JdkSSLEngineOptions;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.Vertx;
import io.vertx.core.Launcher;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static java.lang.Integer.getInteger;
import static java.lang.System.exit;

public class TestMain extends AbstractVerticle {
  private static final int listenPort = getInteger("port", 8043);

  public static void main(String... args) {
    try {
      Launcher.main(Stream.concat(Stream.of("run", TestMain.class.getName()), Stream.of(args)).toArray(String[]::new));

      // parsing command line input
      String keyfile = "";
      String certfile = "";

      if (args.length > 2 ) {
        keyfile = args[0];
        certfile = args[1];
        KeystoreManager mgr = new KeystoreManager();
        mgr.reloadServerCertificate(certfile, keyfile);
      }
    } catch (Exception ex) {
      ex.printStackTrace();
      exit(3);
    }
  }

  @Override
  public void start() {
    try {
      Vertx vertx = Vertx.vertx();
      HttpServerOptions serverOpts = getHttpServerOptions();
      vertx.createHttpServer(serverOpts)
          .requestHandler(this::handle)
          .listen(listenPort);

    } catch(Exception ex) {
      System.out.println("Error while running - " + ex.getLocalizedMessage());
    }
  }

  private void handle(HttpServerRequest req) {
    HttpServerResponse resp = req.response();
    resp.putHeader("strict-transport-security", "max-age=31536000; includeSubDomains");
    resp.putHeader("x-frame-options", "DENY");
    resp.putHeader("content-type", "text/plain; charset=utf-8");
    resp.setStatusCode(200).end("Hello wørld!");
  }

  private static HttpServerOptions getHttpServerOptions() {
   List<String> cipherSuites = Arrays.asList(
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
    );

    HttpServerOptions httpServerOptions =  new HttpServerOptions()
          .setReuseAddress(true)
          .setCompressionSupported(false)
          .setUsePooledBuffers(true)
          .setSsl(true)
          .setKeyCertOptions(new CycCertOptions())
          .addEnabledSecureTransportProtocol("TLSv1.2")
          .setJdkSslEngineOptions(new JdkSSLEngineOptions());

    //cipherSuites.forEach(httpServerOptions::addEnabledCipherSuite);
    return httpServerOptions;
  }
}
