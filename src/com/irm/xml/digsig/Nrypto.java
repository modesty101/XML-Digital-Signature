package com.irm.xml.digsig;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Nrypto {
	/**
	 * 사용할 암호화 알고리즘을 선언한다.
	 */
	private static final String ALGORITHM = "RSA";

	/**
	 * 공개키와 개인키를 1024 바이트로 생성한다. 
	 * 그리고 공개키와 개인키를 저장한다. (Public.key / Private.key)
	 * 
	 * @throws NoSuchAlgorithmException
	 */
	private KeyPair generateKeyPair() {
		KeyPair keyPair = null;
		KeyPairGenerator keyGen;
		try {
			// ALGORITHM(RSA)에 해당하는 키쌍을 리턴
			keyGen = KeyPairGenerator.getInstance(ALGORITHM);
			// 키의 길이를 1024 초기화
			keyGen.initialize(1024);
			// 키 생성
			keyPair = keyGen.genKeyPair();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		return keyPair;
	}

	/**
	 * 개인키를 생성한다.
	 * 
	 * @param filePath , 개인키의 경로
	 * @return privateKey
	 */
	public PrivateKey storedPrivateKey(String filePath) {
		PrivateKey privateKey = null;
		byte[] keyData = getKey(filePath);
		// 개인키를 PKCS8 표준으로 인코딩
		PKCS8EncodedKeySpec encodePrivateKey = new PKCS8EncodedKeySpec(keyData);
		KeyFactory keyFactory = null;

		try {
			// RSA 알고리즘을 받아온다
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		try {
			// 개인키를 생성한다.
			privateKey = keyFactory.generatePrivate(encodePrivateKey);
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return privateKey;
	}

	/**
	 * 공개키를 생성한다
	 * 
	 * @param filePath , 공개키의 경로
	 * @return publicKey
	 */
	public PublicKey storedPublicKey(String filePath) {
		PublicKey publicKey = null;
		byte[] keyData = getKey(filePath);
		KeyFactory keyFactory = null;

		try {
			// RSA 알고리즘을 받아온다
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		X509EncodedKeySpec encodePublicKey = new X509EncodedKeySpec(keyData);

		try {
			// 공개키를 생성한다.
			publicKey = keyFactory.generatePublic(encodePublicKey);
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}

		return publicKey;
	}

	/**
	 * 폴더 안에 개인키와 공개키를 저장한다.
	 * 
	 * @param dirPath
	 */
	public void storeKeyPair(String dirPath) {
		// 키 쌍 -> 생성 함수 호출
		KeyPair keyPair = generateKeyPair();
		// 키 쌍에서 privatekey를 리턴
		PrivateKey privateKey = keyPair.getPrivate();
		// 키 쌍에서 pulbickey를 리턴
		PublicKey publicKey = keyPair.getPublic();

		storeKeys(dirPath + File.separator + "public.key", publicKey);
		storeKeys(dirPath + File.separator + "private.key", privateKey);
	}

	/**
	 * 공개/개인 키를 저장한다.
	 * 
	 * @param filePath , 파일의 이름
	 * @param key
	 */
	private void storeKeys(String filePath, Key key) {
		// 인코딩된 키를 받아온다
		byte[] keyBytes = key.getEncoded();
		// 출력 스트림 준비
		OutputStream outputStream = null;
		try {
			// 파일경로에 인코딩된 키를 저장한다
			outputStream = new FileOutputStream(filePath);
			outputStream.write(keyBytes);
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			// 스트림 null이면 오류!
			if (outputStream != null) {
				try {
					outputStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}

	/**
	 * 배열 안의 (바이트)에서 키를 검색한다/되찾아온다.
	 * 
	 * @param filePath
	 * @return buffer
	 */
	private byte[] getKey(String filePath) {
		File file = new File(filePath);
		// 파일의 길이만큼 할당한다
		byte[] buffer = new byte[(int) file.length()];
		FileInputStream fis = null;

		try {
			fis = new FileInputStream(file);
			fis.read(buffer);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (fis != null) {
				try {
					fis.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}

		return buffer;
	}

	/**
	 * 키 쌍의 생성 여부를 확인한다.
	 * 
	 * Before: public boolean areKeysPresent(String filePath)
	 * 
	 * @return flag indicating if the pair of keys were generated.
	 */
	public boolean areKeysPresent() {
		File privateKey = new File("keys" + File.separator + "private.key");
		File publicKey = new File("keys" + File.separator + "public.key");

		if (privateKey.exists() && publicKey.exists()) {
			return true;
		}
		return false;
	}
}
