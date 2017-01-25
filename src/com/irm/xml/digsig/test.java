package com.irm.xml.digsig;

import java.io.File;
import java.util.Scanner;

public class Test {

	public static void main(String[] args) throws Exception {
		Scanner scan1 = new Scanner(System.in);
		Scanner scan2 = new Scanner(System.in);
		Scanner scan3 = new Scanner(System.in);
		Scanner scan4 = new Scanner(System.in);
		Nrypto Nrypto = new Nrypto();
		
		GenRsaSig.genRsaSig("a.jpg");
		
		UseBase64.main();
		
		System.out.println("XML-Digital-Signature");
		System.out.println("---------------------");

		System.out.print("저장할 키 쌍의 위치 : ");
		String dirPath = scan1.nextLine();
		
		System.out.print("생성할 XML 파일의 이름 : ");
		String XmlFileName = scan2.nextLine();

		System.out.print("서명할 XML 파일의 이름 : ");
		String SignXmlName = scan3.nextLine();

		System.out.print("서명된 XML 파일의 이름 : ");
		String SignedXmlName = scan4.nextLine();
		System.out.println();

		CreateXML.extractEncodingValue("decode.txt",XmlFileName);
		
		String keyPairPath = dirPath;		
		if (Nrypto.areKeysPresent()) {
			System.out.println("Keys are already existed..!!");
		} else {
			System.out.println("Private & Public Keys generating...");
			System.out.println("===================================");
			System.out.println("Complete.");
			Nrypto.storeKeyPair(keyPairPath);
		}

		// String oriXmlPath = "Yeah.xml";
		String oriXmlPath =  SignXmlName;
		// String destSignedXmlPath = "SignedYeah.xml";
		String destSignedXmlPath = SignedXmlName;
		String privateKeyPath = "keys" + File.separator + "private.key";
		String publicKeyPath = "keys" + File.separator + "public.key";

		SignXmlDigSig genSig = new SignXmlDigSig();
		genSig.generateXmlDigSig(oriXmlPath, destSignedXmlPath, privateKeyPath, publicKeyPath);

		SignXmlDigSig.testSignedXML(destSignedXmlPath, publicKeyPath);
	//	SignXmlDigSig.testSignedTamperedXMLDoc("DefaceXML.xml",publicKeyPath);
		
		
	}
}
