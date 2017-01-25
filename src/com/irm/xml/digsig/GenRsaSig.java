package com.irm.xml.digsig;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Signature;

public class GenRsaSig {

	public static void genRsaSig(String fileName) {
		try {
			String keyPath = "keys";
			String privateKeyPath = "keys" + File.separator + "private.key";
			String publicKeyPath = "keys" + File.separator + "public.key";
			Nrypto Nrypto = new Nrypto();
			Nrypto.storeKeyPair(keyPath);

			// Get an instance of Signature object and initialize it.
			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initSign(Nrypto.storedPrivateKey(privateKeyPath));
			// signature.initSign(privateKey);

			// Supply the data to be signed to the Signature object
			// using the update() method and generate the digital
			// signature.
			byte[] bytes = Files.readAllBytes(Paths.get(fileName));
			signature.update(bytes);
			byte[] digitalSignature = signature.sign();

			Files.write(Paths.get("signature"), digitalSignature);
			Files.write(Paths.get("publickey"), Nrypto.storedPublicKey(publicKeyPath).getEncoded());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
