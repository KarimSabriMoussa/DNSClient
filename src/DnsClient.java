import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DnsClient {

	private static int timeout = 5;
	private static int retries = 3;
	private static int port = 53;
	private static int type = 1;
	private static String ipAddress;
	private static String name;

	public static void main(String[] args) {
		parse(args);
		createRequest();
	}

	private static DatagramPacket createRequest() {

		DatagramSocket clientSocket = null;

		Random random = new Random();
		short id = (short) random.nextInt(1 << 16);

		byte[] idBytes = ByteBuffer.allocate(2).putShort(id).array();

		ByteArrayOutputStream stream = new ByteArrayOutputStream();

		byte[] bytes = { (byte) 0x01, (byte) 0x00 };
		byte[] QDCount = { (byte) 0x00, (byte) 0x00 };
		byte[] ANCount = { (byte) 0x00, (byte) 0x00 };
		byte[] NSCount = { (byte) 0x00, (byte) 0x00 };
		byte[] ARCount = { (byte) 0x00, (byte) 0x00 };

		byte[] qname = domainToBytes();

		byte[] qtype = { (byte) 0x00, (byte) type };
		byte[] qclass = { (byte) 0x00, (byte) 0x01 };

		try {
			stream.write(idBytes);
			stream.write(bytes);
			stream.write(QDCount);
			stream.write(ANCount);
			stream.write(NSCount);
			stream.write(ARCount);
			stream.write(qname);
			stream.write(qtype);
			stream.write(qclass);
		} catch (IOException e) {
			e.printStackTrace();
		}

		byte[] data = stream.toByteArray();

		for (int i = 0; i < retries; i++) {
			try {
				clientSocket = new DatagramSocket();
				clientSocket.setSoTimeout(timeout * 1000);
			} catch (SocketException e) {
				e.printStackTrace();
			}

			try {
				long startTime = System.currentTimeMillis();
				
				InetAddress inetAddress = getInetAddress();
				DatagramPacket sendPacket = new DatagramPacket(data, data.length, inetAddress, port);
				clientSocket.send(sendPacket);
				data = new byte[512];
				DatagramPacket receivePacket = new DatagramPacket(data, data.length);
				clientSocket.receive(receivePacket);
				
				long endTime = System.currentTimeMillis();
				double interval = (endTime - startTime)/1000.0;
				
				System.out.println("Response received after " + interval + " seconds ( " + i + "retries )");
				return receivePacket;
			} catch (IOException e) {
				e.printStackTrace();
				if (i == retries - 1) {
					System.out.println("Max number of retries: " + retries + " was exceeded");
				}
			}
		}
		return null;

	}

	private static InetAddress getInetAddress() {
		InetAddress address = null;
		String[] subStrings = ipAddress.split("\\.");


		ByteArrayOutputStream stream = new ByteArrayOutputStream();

		for (String s : subStrings) {
			stream.write(Integer.parseInt(s));
		}

		try {
			address = InetAddress.getByAddress(stream.toByteArray());
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}

		return address;
	}

	private static byte[] domainToBytes() {

		ByteArrayOutputStream stream = new ByteArrayOutputStream();

		String[] labels = name.split("\\.");
		for (String s : labels) {
			stream.write(s.length());
			byte[] byteArray = s.getBytes(StandardCharsets.US_ASCII);
			for (byte b : byteArray) {
				stream.write(b);
			}
		}

		return stream.toByteArray();
	}

	private static void parse(String[] args) {
		ArrayList<String> argList = new ArrayList<String>(Arrays.asList(args));

		int i = argList.indexOf("-t");
		if (i != -1) {
			if (isInteger(argList.get(i + 1))) {
				timeout = Integer.parseInt(argList.get(i + 1));
			} else {
				displayUsage();
			}
		}

		i = argList.indexOf("-r");
		if (i != -1) {
			if (isInteger(argList.get(i + 1))) {
				retries = Integer.parseInt(argList.get(i + 1));
			} else {
				displayUsage();
			}
		}

		i = argList.indexOf("-p");
		if (i != -1) {
			if (isInteger(argList.get(i + 1))) {
				port = Integer.parseInt(argList.get(i + 1));
			} else {
				displayUsage();
			}
		}

		i = argList.indexOf("-ns");
		if (i != -1) {
			if (type == 1) {
				type = 2;
			} else {
				displayUsage();
			}
		}

		i = argList.indexOf("-mx");
		if (i != -1) {
			if (type == 1) {
				type = 15;
			} else {
				displayUsage();
			}
		}

		String server = argList.get(argList.size() - 2);

		if (server.startsWith("@")) {
			ipAddress = server.substring(1);
		} else {
			displayUsage();
		}

		String domainRegex = "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z]{2,6}";

		Pattern domainPattern = Pattern.compile(domainRegex);

		String domainName = argList.get(argList.size() - 1);
		Matcher domainMatcher = domainPattern.matcher(domainName);
		if (domainMatcher.matches()) {
			name = domainName;
		} else {
			displayUsage();
		}

	}

	private static void displayUsage() {
		System.out.println("Invalid Input");
		System.out
				.println("Proper Usage: java DnsClient [-t timeout] [-r max-retries] [-p port] [-mx|-ns] @server name");
	}

	private static boolean isInteger(String strNum) {
		if (strNum == null) {
			return false;
		}
		try {
			Integer.parseInt(strNum);
		} catch (NumberFormatException nfe) {
			return false;
		}
		return true;
	}
}
