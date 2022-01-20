package cz.valiasek;

import java.io.File;
import java.io.FileOutputStream;
import java.util.concurrent.Callable;
import java.util.logging.Logger;

import cz.valiasek.config.Config;
import cz.valiasek.model.SignatureModel;
import cz.valiasek.task.SigningTask;
import eu.europa.esig.dss.signature.RemoteDocumentSignatureServiceImpl;
import eu.europa.esig.dss.utils.Utils;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import eu.europa.esig.dss.*;
import eu.europa.esig.dss.signature.RemoteDocumentSignatureService;


@Command(
        name = "sdat-signer",
        mixinStandardHelpOptions = true,
        version = "1.0.0",
        description = "Signs input gzip file for czech national bank SOAP webservice ZaslaniVstupniZpravy"
)
public class SdatSigner implements Callable<Integer> {

    @Option(names = {"-i", "--input"}, description = "Input GZIP file")
    private File fileToSign;

    @Option(names = {"-c", "--pkcs"}, description = "PKCS#12 certificate with key")
    private File pkcsFile;

    @Option(names = {"-p", "--pwd"}, description = "PKCS#12 certificate password")
    private String pkcsPassword;

    @Option(names = {"-o", "--output"}, description = "Output XMLDSIG signature file")
    private File fileToSave;

    private static final Logger LOG = Logger.getLogger(SdatSigner.class.getName());

    public static void main(String[] args) {
        int exitCode = new CommandLine(new SdatSigner()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {
        Config config = new Config();
        RemoteDocumentSignatureService<RemoteDocument, RemoteSignatureParameters> service = config.remoteSignatureService();
        SignatureModel model = new SignatureModel();
        // no container
        model.setAsicContainerType(null);
        // XAdES
        model.setSignatureForm(SignatureForm.XAdES);
        // Detached
        model.setSignaturePackaging(SignaturePackaging.DETACHED);
        model.setDigestAlgorithm(DigestAlgorithm.SHA256);
        model.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        model.setTokenType(SignatureTokenType.PKCS12);
        model.setPkcsFile(this.pkcsFile);
        model.setPassword(this.pkcsPassword);
        model.setFileToSign(this.fileToSign);
        SigningTask task = new SigningTask(service, model);
        DSSDocument document = task.call();
        this.save(document, this.fileToSave);
        return 0;
    }

    private void save(DSSDocument signedDocument, File fileToSave) {
        try (FileOutputStream fos = new FileOutputStream(fileToSave)) {
            Utils.copy(signedDocument.openStream(), fos);
        } catch (Exception e) {
            LOG.info("Nepodařilo se uložit soubor : " + e.getMessage());
        }
    }
}
