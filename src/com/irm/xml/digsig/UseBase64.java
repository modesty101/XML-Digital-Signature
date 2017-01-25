package com.irm.xml.digsig;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Scanner;

import org.apache.commons.codec.binary.Base64;

public class UseBase64 {

	/* IS_CHUNKED의 논리값 참일 경우, 76자씩 개행 문자(&#13;)와 함께 인코딩된다. */
	private static final boolean IS_CHUNKED = false;

	/**
	 * Base64 인코딩할 파일을 불러오고 저장합니다.
	 * 
	 * @param encodeFile
	 * @param encodingFile
	 * @param isChunked
	 * @throws IOException
	 */
	public static void encodeFile(String encodeFile, String encodingFile, boolean isChunked) throws IOException {

		byte[] encodingImage = Base64.encodeBase64(loadFile(encodeFile), isChunked);

		writeFile(encodingFile, encodingImage);
	}

	/**
	 * Base64 디코딩할 파일을 불러오고 저장합니다.
	 * 
	 * @param decodeFile
	 * @param decodedFile
	 * @throws Exception
	 */
	public static void decodeFile(String decodeFile, String decodedFile) throws Exception {

		byte[] bytes = Base64.decodeBase64(loadFile(decodeFile));

		writeFile(decodedFile, bytes);
	}

	/**
	 * 파일을 불러옵니다.
	 * 
	 * @param encodeFile
	 * @return bytes
	 * @throws IOException
	 */
	public static byte[] loadFile(String fileName) throws IOException {
		File file = new File(fileName);
		int len = (int) file.length();

		BufferedInputStream reader = new BufferedInputStream(new FileInputStream(file));
		byte[] bytes = new byte[len];
		reader.read(bytes, 0, len);
		reader.close();

		return bytes;
	}

	/**
	 * 파일을 저장합니다.
	 * 
	 * @param fileName
	 * @param encodedFile
	 * @throws IOException
	 */
	public static void writeFile(String fileName, byte[] encodedFile) throws IOException {
		File file = new File(fileName);
		BufferedOutputStream writer = new BufferedOutputStream(new FileOutputStream(file));
		writer.write(encodedFile);
		writer.flush();
		writer.close();
	}

	/**
	 * 인코딩 테스트
	 * @return 
	 * 
	 * @throws Exception
	 */
	public static void main() throws Exception {
		Scanner scan1 = new Scanner(System.in);
		Scanner scan2 = new Scanner(System.in);
		Scanner scan3 = new Scanner(System.in);
		
		System.out.print("인코딩할 파일의 이름 : ");
		String fileName = scan1.nextLine();
		System.out.print("인코딩될 파일의 이름 : ");
		String encFileName = scan2.nextLine();
		System.out.print("디코딩될 파일의 이름 : ");
		String decFileName = scan3.nextLine();
		
		UseBase64.encodeFile(fileName, encFileName, IS_CHUNKED);
		UseBase64.decodeFile(encFileName, decFileName);
	}
}
