package cz.valiasek.config;

import com.zaxxer.hikari.HikariDataSource;
import eu.europa.esig.dss.asic.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.client.crl.JdbcCacheCRLSource;
import eu.europa.esig.dss.client.crl.OnlineCRLSource;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.client.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.client.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.client.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.RemoteDocumentSignatureServiceImpl;
import eu.europa.esig.dss.token.KeyStoreSignatureTokenConnection;
import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.x509.tsp.MockTSPSource;
import eu.europa.esig.dss.xades.signature.XAdESService;

import javax.sql.DataSource;
import java.io.IOException;
import java.security.KeyStore;

public class Config {
    private KeyStoreSignatureTokenConnection token = new KeyStoreSignatureTokenConnection(
           this.getClass().getResourceAsStream("self-signed-tsa.p12"),
        "PKCS12",
            new KeyStore.PasswordProtection("ks-password".toCharArray())
    );

    public Config() throws IOException {
    }

    public DataSource dataSource() {
        HikariDataSource ds = new HikariDataSource();
        ds.setPoolName("DSS-Hikari-Pool");
        ds.setJdbcUrl("jdbc:hsqldb:mem:testdb");
        ds.setDriverClassName("org.hsqldb.jdbcDriver");
        ds.setUsername("sa");
        ds.setPassword("");
        ds.setAutoCommit(false);
        return ds;
    }

    public MockTSPSource tspSource() {
        MockTSPSource tspSource = new MockTSPSource();
        tspSource.setToken(this.token);
        tspSource.setAlias("self-signed-tsa");
        return tspSource;
    }

    public CommonsDataLoader dataLoader() {
        CommonsDataLoader dataLoader = new CommonsDataLoader();
        // dataLoader.setProxyConfig(proxyConfig);
        return dataLoader;
    }

    public OCSPDataLoader ocspDataLoader() {
        OCSPDataLoader ocspDataLoader = new OCSPDataLoader();
        // ocspDataLoader.setProxyConfig(proxyConfig);
        return ocspDataLoader;
    }

    public FileCacheDataLoader fileCacheDataLoader() {
        FileCacheDataLoader fileCacheDataLoader = new FileCacheDataLoader();
        fileCacheDataLoader.setDataLoader(dataLoader());
        // Per default uses "java.io.tmpdir" property
        // fileCacheDataLoader.setFileCacheDirectory(new File("/tmp"));
        return fileCacheDataLoader;
    }

    public OnlineCRLSource onlineCRLSource() {
        OnlineCRLSource onlineCRLSource = new OnlineCRLSource();
        onlineCRLSource.setDataLoader(dataLoader());
        return onlineCRLSource;
    }

    public JdbcCacheCRLSource cachedCRLSource() throws Exception {
        JdbcCacheCRLSource jdbcCacheCRLSource = new JdbcCacheCRLSource();
        jdbcCacheCRLSource.setDataSource(dataSource());
        jdbcCacheCRLSource.setCachedSource(onlineCRLSource());
        return jdbcCacheCRLSource;
    }

    public OnlineOCSPSource ocspSource() {
        OnlineOCSPSource onlineOCSPSource = new OnlineOCSPSource();
        onlineOCSPSource.setDataLoader(ocspDataLoader());
        return onlineOCSPSource;
    }

    public TrustedListsCertificateSource trustedListSource() {
        return new TrustedListsCertificateSource();
    }

    public CertificateVerifier certificateVerifier() throws Exception {
        CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        certificateVerifier.setTrustedCertSource(trustedListSource());
        certificateVerifier.setCrlSource(cachedCRLSource());
        certificateVerifier.setOcspSource(ocspSource());
        certificateVerifier.setDataLoader(dataLoader());

        // Default configs
        certificateVerifier.setExceptionOnMissingRevocationData(false);
        certificateVerifier.setCheckRevocationForUntrustedChains(false);

        return certificateVerifier;
    }

    public CAdESService cadesService() throws Exception {
        CAdESService service = new CAdESService(certificateVerifier());
        service.setTspSource(tspSource());
        return service;
    }

    public XAdESService xadesService() throws Exception {
        XAdESService service = new XAdESService(certificateVerifier());
        service.setTspSource(tspSource());
        return service;
    }

    public PAdESService padesService() throws Exception {
        PAdESService service = new PAdESService(certificateVerifier());
        service.setTspSource(tspSource());
        return service;
    }

    public ASiCWithCAdESService asicWithCadesService() throws Exception {
        ASiCWithCAdESService service = new ASiCWithCAdESService(certificateVerifier());
        service.setTspSource(tspSource());
        return service;
    }

    public ASiCWithXAdESService asicWithXadesService() throws Exception {
        ASiCWithXAdESService service = new ASiCWithXAdESService(certificateVerifier());
        service.setTspSource(tspSource());
        return service;
    }

    public RemoteDocumentSignatureServiceImpl remoteSignatureService() throws Exception {
        RemoteDocumentSignatureServiceImpl service = new RemoteDocumentSignatureServiceImpl();
        service.setAsicWithCAdESService(asicWithCadesService());
        service.setAsicWithXAdESService(asicWithXadesService());
        service.setCadesService(cadesService());
        service.setXadesService(xadesService());
        service.setPadesService(padesService());
        return service;
    }
}