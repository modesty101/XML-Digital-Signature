package com.irm.xml.digsig;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class IO {

	/**
	 * Load the file to encode or file to be edited
	 * 
	 * @param encodeFile
	 * @return
	 * @throws IOException
	 */
	public static byte[] loadFile(String encodeFile) throws IOException {
		File file = new File(encodeFile);
		int len = (int) file.length();

		BufferedInputStream reader = new BufferedInputStream(new FileInputStream(file));
		byte[] bytes = new byte[len];
		reader.read(bytes, 0, len);
		reader.close();

		return bytes;
	}

	/**
	 * Write the encoded file or decoded file
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
}
