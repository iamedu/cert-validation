(defproject cert-validation "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [org.bouncycastle/bcprov-jdk14 "1.51"]
                 [org.bouncycastle/bcpkix-jdk14 "1.51"]
                 [com.relayrides/pushy "0.4.1"]]
  :main ^:skip-aot cert-validation.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})
