package cz.valiasek.task;

import cz.valiasek.exception.ApplicationException;
import cz.valiasek.model.SignatureModel;
import eu.europa.esig.dss.*;
import eu.europa.esig.dss.signature.RemoteDocumentSignatureService;
import eu.europa.esig.dss.token.*;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;

import java.io.IOException;
import java.security.KeyStore.PasswordProtection;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Callable;

public class SigningTask implements Callable<DSSDocument> {

	private RemoteDocumentSignatureService<RemoteDocument, RemoteSignatureParameters> service;
	private SignatureModel model;

	public SigningTask(RemoteDocumentSignatureService<RemoteDocument, RemoteSignatureParameters> service, SignatureModel model) {
		this.service = service;
		this.model = model;
	}

	public DSSDocument call() throws Exception {
		SignatureTokenConnection token = getToken(model);
		List<DSSPrivateKeyEntry> keys = token.getKeys();
		DSSPrivateKeyEntry signer = getSigner(keys);

		FileDocument fileToSign = new FileDocument(model.getFileToSign());
		RemoteDocument toSignDocument = RemoteConverter.toRemoteDocument(fileToSign);
		RemoteSignatureParameters parameters = buildParameters(signer);

		ToBeSigned toBeSigned = getDataToSign(toSignDocument, parameters);
		SignatureValue signatureValue = signDigest(token, signer, toBeSigned);
		return signDocument(toSignDocument, parameters, signatureValue);
	}

	private RemoteSignatureParameters buildParameters(DSSPrivateKeyEntry signer) {
		RemoteSignatureParameters parameters = new RemoteSignatureParameters();
		parameters.setAsicContainerType(model.getAsicContainerType());
		parameters.setDigestAlgorithm(model.getDigestAlgorithm());
		parameters.setSignatureLevel(model.getSignatureLevel());
		parameters.setSignaturePackaging(model.getSignaturePackaging());
		BLevelParameters bLevelParams = new BLevelParameters();
		bLevelParams.setSigningDate(new Date());
		parameters.setBLevelParams(bLevelParams);
		parameters.setSigningCertificate(new RemoteCertificate(signer.getCertificate().getEncoded()));
		parameters.setEncryptionAlgorithm(signer.getEncryptionAlgorithm());
		CertificateToken[] certificateChain = signer.getCertificateChain();
		if (Utils.isArrayNotEmpty(certificateChain)) {
			List<RemoteCertificate> certificateChainList = new ArrayList<RemoteCertificate>();
			for (CertificateToken certificateToken : certificateChain) {
				certificateChainList.add(new RemoteCertificate(certificateToken.getEncoded()));
			}
			parameters.setCertificateChain(certificateChainList);
		}

		return parameters;
	}

	private ToBeSigned getDataToSign(RemoteDocument toSignDocument, RemoteSignatureParameters parameters) throws Exception {
		ToBeSigned toBeSigned = null;
		try {
			toBeSigned = service.getDataToSign(toSignDocument, parameters);
		} catch (Exception e) {
			throwException("Unable to compute the digest to sign", e);
		}
		return toBeSigned;
	}

	private SignatureValue signDigest(SignatureTokenConnection token, DSSPrivateKeyEntry signer, ToBeSigned toBeSigned) throws Exception {
		SignatureValue signatureValue = null;
		try {
			signatureValue = token.sign(toBeSigned, model.getDigestAlgorithm(), signer);
		} catch (Exception e) {
			throwException("Unable to sign the digest", e);
		}
		return signatureValue;
	}

	private DSSDocument signDocument(RemoteDocument toSignDocument, RemoteSignatureParameters parameters, SignatureValue signatureValue) throws Exception {
		DSSDocument signDocument = null;
		try {
			signDocument = RemoteConverter.toDSSDocument(service.signDocument(toSignDocument, parameters, signatureValue));
		} catch (Exception e) {
			throwException("Unable to sign the document", e);
		}
		return signDocument;
	}

	private DSSPrivateKeyEntry getSigner(List<DSSPrivateKeyEntry> keys) throws Exception {
		DSSPrivateKeyEntry selectedKey = null;
		if (Utils.isCollectionEmpty(keys)) {
			throwException("No certificate found", null);
		} else if (Utils.collectionSize(keys) == 1) {
			selectedKey = keys.get(0);
		} else {
			throwException("Cannot decide which certificate key use for signing, multiple keys found in certificate.", null);
		}
		return selectedKey;
	}

	private SignatureTokenConnection getToken(SignatureModel model) throws IOException {
		switch (model.getTokenType()) {
		case PKCS11:
			return new Pkcs11SignatureToken(model.getPkcsFile().getAbsolutePath(), new PasswordProtection(model.getPassword().toCharArray()));
		case PKCS12:
			return new Pkcs12SignatureToken(model.getPkcsFile(), new PasswordProtection(model.getPassword().toCharArray()));
		case MSCAPI:
			return new MSCAPISignatureToken();
		default:
			throw new IllegalArgumentException("Unsupported token type " + model.getTokenType());
		}
	}

	private void throwException(String message, Exception e) {
		String exceptionMessage = message + ((e != null) ? " : " + e.getMessage() : "");
		throw new ApplicationException(exceptionMessage, e);
	}

}
