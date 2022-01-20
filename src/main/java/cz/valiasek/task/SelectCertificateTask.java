package cz.valiasek.task;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.x509.CertificateToken;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

public class SelectCertificateTask implements Callable<DSSPrivateKeyEntry> {

	private List<DSSPrivateKeyEntry> keys;

	public SelectCertificateTask(List<DSSPrivateKeyEntry> keys) {
		this.keys = keys;
	}

	@Override
	public DSSPrivateKeyEntry call() throws Exception {
		Map<String, DSSPrivateKeyEntry> map = new HashMap<String, DSSPrivateKeyEntry>();
		DSSPrivateKeyEntry firstKey = null;
		for (DSSPrivateKeyEntry dssPrivateKeyEntry : keys) {
			CertificateToken certificate = dssPrivateKeyEntry.getCertificate();
			String text = DSSASN1Utils.getHumanReadableName(certificate) + " (" + certificate.getSerialNumber() + ")";
			firstKey = dssPrivateKeyEntry;
			break;
			// map.put(text, dssPrivateKeyEntry);
		}
		return firstKey;
		
		/*
		ChoiceDialog<String> dialog = new ChoiceDialog<String>(keySet.iterator().next(), keySet);
		dialog.setHeaderText("Select your certificate");
		Optional<String> result = dialog.showAndWait();
		
		try {
			return map.get(result.get());
		} catch (NoSuchElementException e) {
			return null;
		}
		 */
	}
}
