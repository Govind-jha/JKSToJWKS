import com.nimbusds.jose.jwk.JWKSet;

import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class PublicKeyToJWKS {

    public static void main(String[] args) throws Exception {
        File pub = File.createTempFile("pub", ".pem");

        BufferedWriter bw1 = new BufferedWriter(new FileWriter(pub));
        bw1.write("-----BEGIN CERTIFICATE-----\n" +
                        "MIIFpjCCBI6gAwIBAgIEWf9qjjANBgkqhkiG9w0BAQsFADBEMQswCQYDVQQGEwJH\n" +
                        "QjEUMBIGA1UEChMLT3BlbkJhbmtpbmcxHzAdBgNVBAMTFk9wZW5CYW5raW5nIElz\n" +
                        "c3VpbmcgQ0EwHhcNMTkwNjEyMTUzNDUwWhcNMjEwNjEyMTYwNDUwWjBhMQswCQYD\n" +
                        "VQQGEwJHQjEUMBIGA1UEChMLT3BlbkJhbmtpbmcxGzAZBgNVBAsTEjAwMTU4MDAw\n" +
                        "MDE2aTQ0akFBQTEfMB0GA1UEAxMWMXF0MDZFdXpIUU9PdTJDS25vMzA0VDCCASIw\n" +
                        "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM4ehOEM/t4p6/FpPl9tpDy1AlCX\n" +
                        "AwPzeP/k0SDstTXdmbXG3di4EKXWm3t/zwSyi4kNSWPbh5v+5FlMdCoM4Y8m9PKC\n" +
                        "ghuJ7rTeigmXMLiD1Opw441vDs7LtAspXb2GOwkcjODZQC7v4rlfLdOff7Ms3I+w\n" +
                        "Mu3R68z6RWtOkbI+oceqhMWkCZ7FJKk5jqtGon/DJrMfG/xfxY+GnuBaWe9MTA9o\n" +
                        "IISMTklqmdnOKay1V3rfi8F5wd+GGIk/xJVyjlSgHbV5NhjdLyfhY6zz5+quaLG+\n" +
                        "Ffz/7gep9M/t72mkCmutxQfS81rn9LqZ/w4DvdQSH7vzvjt7iQRaO/N49QkCAwEA\n" +
                        "AaOCAoEwggJ9MA4GA1UdDwEB/wQEAwIHgDAgBgNVHSUBAf8EFjAUBggrBgEFBQcD\n" +
                        "AQYIKwYBBQUHAwIwggFSBgNVHSAEggFJMIIBRTCCAUEGCysGAQQBqHWBBgEBMIIB\n" +
                        "MDA1BggrBgEFBQcCARYpaHR0cDovL29iLnRydXN0aXMuY29tL3Byb2R1Y3Rpb24v\n" +
                        "cG9saWNpZXMwgfYGCCsGAQUFBwICMIHpDIHmVGhpcyBDZXJ0aWZpY2F0ZSBpcyBz\n" +
                        "b2xlbHkgZm9yIHVzZSB3aXRoIE9wZW4gQmFua2luZyBMaW1pdGVkIGFuZCBhc3Nv\n" +
                        "Y2lhdGVkIE9wZW4gQmFua2luZyBTZXJ2aWNlcy4gSXRzIHJlY2VpcHQsIHBvc3Nl\n" +
                        "c3Npb24gb3IgdXNlIGNvbnN0aXR1dGVzIGFjY2VwdGFuY2Ugb2YgdGhlIE9wZW4g\n" +
                        "QmFua2luZyBMaW1pdGVkIENlcnRpZmljYXRlIFBvbGljeSBhbmQgcmVsYXRlZCBk\n" +
                        "b2N1bWVudHMgdGhlcmVpbi4wcgYIKwYBBQUHAQEEZjBkMCYGCCsGAQUFBzABhhpo\n" +
                        "dHRwOi8vb2IudHJ1c3Rpcy5jb20vb2NzcDA6BggrBgEFBQcwAoYuaHR0cDovL29i\n" +
                        "LnRydXN0aXMuY29tL3Byb2R1Y3Rpb24vaXNzdWluZ2NhLmNydDA/BgNVHR8EODA2\n" +
                        "MDSgMqAwhi5odHRwOi8vb2IudHJ1c3Rpcy5jb20vcHJvZHVjdGlvbi9pc3N1aW5n\n" +
                        "Y2EuY3JsMB8GA1UdIwQYMBaAFJ9Jv042p6zDDyvIR/QfKRvAeQsFMB0GA1UdDgQW\n" +
                        "BBR1q3FOJ/xApPTL6B89dEijpgMIcjANBgkqhkiG9w0BAQsFAAOCAQEAOqm/tUcC\n" +
                        "JmSXlesGVrdppwfMFm5SMQxbFP/59OAr29Qo8X5wt2zzk/XHh3Kv8Ls2A/TrPjVq\n" +
                        "Dyrxcc0g8P1Fo47VLHZLP7cI9gxDWKnss1GN4v7p0HuPPXGIOO7twm3hMUoENAJK\n" +
                        "7muWJDhFVboyg0l1AYsOUYnh92NazwxAIzU+0ezPBgevL8l/+Xt9hPJCmWAms+ZT\n" +
                        "0fJtWiLuZg/L+ucxxhNClkPLaqm0WygplVAlt+Ep/AnusoQUc5v24ITimNg+4HF4\n" +
                        "BVdlEZgMC99sYazxjmUNfiQ3rXlfrJlwIfOgfRpLBVZubUUVtuJ/ZkjfezIa7H9c\n" +
                        "VZbEwHiH36Q/Ug==\n" +
                        "-----END CERTIFICATE-----");
        bw1.close();

        KeyStore jks = PemReader.createKeyStore("cert_alias", pub, "intuit01");

        JWKSet jwkFromPem = getJwkFromPem(jks);

        System.out.println(jwkFromPem);
    }

    public static JWKSet getJwkFromPem(KeyStore jks) {
        //"application/jwk-set+json; charset=UTF-8"

        JWKSet jwkSet = null;
        try {
            jwkSet = JWKSet.load(jks, null);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        return jwkSet;
    }

}

class PemReader{
    /**
     * Create a KeyStore from standard PEM file
     */
    public static KeyStore createKeyStore(String alias, File certificatePem, final String password) throws Exception {
        final X509Certificate[] cert = createCertificates(certificatePem);
        final KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(null);

        keystore.setCertificateEntry(alias, cert[0]);
        return keystore;
    }

    private static X509Certificate[] createCertificates(File certificatePem) throws Exception {
        final List<X509Certificate> result = new ArrayList<>();
        final BufferedReader r = new BufferedReader(new FileReader(certificatePem));
        String s = r.readLine();
        if (s == null || !s.contains("BEGIN CERTIFICATE")) {
            r.close();
            throw new IllegalArgumentException("No CERTIFICATE found");
        }
        StringBuffer b = new StringBuffer();
        while (s != null) {
            if (s.contains("END CERTIFICATE")) {
                String hexString = b.toString();
                final byte[] bytes = DatatypeConverter.parseBase64Binary(hexString);
                X509Certificate cert = generateCertificateFromDER(bytes);
                result.add(cert);
                b = new StringBuffer();
            } else {
                if (!s.startsWith("----")) {
                    b.append(s);
                }
            }
            s = r.readLine();
        }
        r.close();

        return result.toArray(new X509Certificate[result.size()]);
    }

    private static X509Certificate generateCertificateFromDER(byte[] certBytes) throws CertificateException {
        final CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certBytes));
    }
}
