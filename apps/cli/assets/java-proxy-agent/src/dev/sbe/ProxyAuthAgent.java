package dev.sbe;

import java.lang.instrument.Instrumentation;
import java.net.Authenticator;
import java.net.PasswordAuthentication;

/** Installs credentials only for SBE's exact per-run loopback proxy. */
public final class ProxyAuthAgent {
    private ProxyAuthAgent() {}

    public static void premain(String ignored, Instrumentation instrumentation) {
        String token = System.getenv("SBE_PROXY_TOKEN");
        String host = System.getProperty("https.proxyHost");
        String portValue = System.getProperty("https.proxyPort");
        if (token == null || token.isEmpty() || host == null || portValue == null) {
            throw new IllegalStateException("SBE proxy agent is missing its runtime configuration");
        }

        int port;
        try {
            port = Integer.parseInt(portValue);
        } catch (NumberFormatException error) {
            throw new IllegalStateException("SBE proxy port is invalid", error);
        }

        if (!"127.0.0.1".equals(host) || port < 1 || port > 65535) {
            throw new IllegalStateException("SBE proxy agent refuses a non-loopback endpoint");
        }
        Authenticator.setDefault(new SbeProxyAuthenticator(host, port, token));
    }

    private static final class SbeProxyAuthenticator extends Authenticator {
        private final String host;
        private final int port;
        private final char[] token;

        private SbeProxyAuthenticator(String host, int port, String token) {
            this.host = host;
            this.port = port;
            this.token = token.toCharArray();
        }

        @Override
        protected PasswordAuthentication getPasswordAuthentication() {
            if (getRequestorType() == RequestorType.PROXY
                    && host.equals(getRequestingHost())
                    && port == getRequestingPort()) {
                return new PasswordAuthentication("sbe", token);
            }
            return null;
        }
    }
}
