(ns cert-validation.core
  (:require [clojure.java.io :as io])
  (:import [org.bouncycastle.jce.provider BouncyCastleProvider]
           [org.bouncycastle.cert.jcajce JcaX509CertificateConverter]
           [org.bouncycastle.openssl.jcajce JcaPEMWriter]
           [org.bouncycastle.openssl PEMParser PEMKeyPair]
           [org.bouncycastle.openssl.jcajce JcaPEMWriter JcaPEMKeyConverter]
           [java.io ByteArrayOutputStream ByteArrayInputStream]
           [java.io OutputStreamWriter InputStreamReader]
           [java.security.cert Certificate]
           [java.security KeyStore Security])
  (:gen-class))

(Security/addProvider
  (BouncyCastleProvider.))

(defn build-pem-stream [p12-stream password-chars]
  (let [out-stream (ByteArrayOutputStream.)
        writer (JcaPEMWriter. (OutputStreamWriter. out-stream))
        keystore (doto (KeyStore/getInstance "PKCS12")
                   (.load p12-stream password-chars))]
    (doseq [alias (enumeration-seq (.aliases keystore))]
      (.writeObject writer (.getCertificate keystore alias))
      (if-let [k (.getKey keystore alias password-chars)]
        (.writeObject writer k)))
    (.flush writer)
    (-> out-stream
        (.toString)
        (.getBytes)
        (ByteArrayInputStream.))))

(defn build-keystore-from-pem-stream [pem-stream]
  (let [pem-parser (PEMParser. (InputStreamReader. pem-stream))
        key-store (KeyStore/getInstance "PKCS12" "BC")
        cert-converter (JcaX509CertificateConverter.)
        key-converter (doto (JcaPEMKeyConverter.)
                        (.setProvider "BC"))
        cert (.readObject pem-parser)
        key (.readObject pem-parser)
        x509-cert (.getCertificate cert-converter cert)
        key-pair (.getKeyPair key-converter key)
        empty-chars (.toCharArray "")
        cert-array (into-array Certificate [x509-cert])]
    (.load key-store nil nil)
    (.setCertificateEntry
      key-store
      "1"
      x509-cert)
    (.setKeyEntry key-store
                  "1"
                  (.getPrivate key-pair)
                  empty-chars
                  cert-array)
    key-store))

(defn -main
  "I don't do a whole lot ... yet."
  [& args]
  (println "Hello, World!"))

(let [is (io/input-stream "hola")
      password (.toCharArray "password")
      pem-stream (build-pem-stream is password)]
  (build-keystore-from-pem-stream pem-stream))

