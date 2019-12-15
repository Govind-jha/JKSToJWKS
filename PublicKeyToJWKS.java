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
                        "" +
                        "-----END CERTIFICATE-----");
        bw1.close();

        KeyStore jks = PemReader.createKeyStore("cert_alias", pub, "secret");

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
