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
		DatagramPacket response = createRequest();
		
		printResponse(response);
	}

	private static void printResponse(DatagramPacket response) {

		byte[] data = response.getData();
//		for(int i = 0; i< data.length; i = i + 2) {
//			String hex1 = Integer.toHexString(data[i]);
//			String hex2 = Integer.toHexString(data[i+1]);
//			System.out.println(hex1+ "\t"+ hex2);
//		}
		String auth = null;

		ByteBuffer buffer = ByteBuffer.wrap(data);

		short responseId = buffer.getShort();
		short flags = buffer.getShort();
		short qdCount = buffer.getShort();
		short anCount =	buffer.getShort();
		short nsCount = buffer.getShort();
		short arCount = buffer.getShort();



		if (((flags >> 10) & 1) == 1) {
			auth = "auth";
		} else {
			auth = "nonauth";
		}

		byte rcode = (byte) (flags & 0x0f);

		if (rcode == 1) {
			System.out.println("ERROR\tFormat error: the name server was unable to interpret the query");
			return;
		} else if (rcode == 2) {
			System.out.println(
					"ERROR\tServer failure: the name server was unable to process this query due to a problem with the name server");
			return;
		} else if (rcode == 3) {
			System.out.println(
					"ERROR\tName error: meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist");
			return;
		} else if (rcode == 4) {
			System.out.println("ERROR\tNot implemented: the name server does not support the requested kind of query");
			return;
		} else if (rcode == 5) {
			System.out.println(
					"ERROR\tRefused: the name server refuses to perform the requested operation for policy reasons");
			return;
		}

		movePointer(buffer); // skip qname
		buffer.getShort(); // qtype
		buffer.getShort(); // qclass

		if (anCount != 0) {
			System.out.println("***Answer Section (" + anCount + "records )***");
		} else {
			System.out.println("NOTFOUND");
		}

		for (int i = 0; i < anCount; i++) {
			movePointer(buffer);
			short type = buffer.getShort();
			short aClass = buffer.getShort();
			int ttl = buffer.getInt();
			short rdLength = buffer.getShort();
			printAnswer(buffer, type, ttl, rdLength, auth);
		}

		for (int i = 0; i < nsCount; i++) {
			movePointer(buffer);
			short type = buffer.getShort();
			short aClass = buffer.getShort();
			int ttl = buffer.getInt();
			short rdLength = buffer.getShort();
			buffer.position(buffer.position() + rdLength);
		}

		if (arCount != 0) {
			System.out.println("***Additional Section (" + arCount + "records )***");
			for (int i = 0; i < arCount; i++) {
				movePointer(buffer);
				short type = buffer.getShort();
				short aClass = buffer.getShort();
				int ttl = buffer.getInt();
				short rdLength = buffer.getShort();
				printAnswer(buffer, type, ttl, rdLength, auth);
			}
		}

	}

	private static void printAnswer(ByteBuffer buffer, short type, int ttl, short rdLength, String auth) {

		int length = rdLength;
		switch (type) {
		case 0x01:
			String ip = getIp(buffer);
			System.out.println("IP\t" + ip + "\t" + ttl + "\t" + auth);
			if (length - 4 > 0) {
				length = (length - 4);
				while (length > 0) {
					buffer.get();
					length = (length - 1);
				}
			}
			break;
		case 0x02:
			String serverName = getAlias(buffer);
			System.out.println("NS\t" + serverName + "\t" + ttl + "\t" + auth);
			break;
		case 0x05:
			String alias = getAlias(buffer);
			System.out.println("CNAME\t" + alias + "\t" + ttl + "\t" + auth);
			break;
		case 0x0f:
			short pref = buffer.getShort();
			String name = getAlias(buffer);
			System.out.println("MX\t" + name + "\t" + pref + "\t" + ttl + "\t" + auth);
			break;
		default:
			System.out.println("Unexpected Error"); // TODO: write specific error
		}

	}

	private static String getAlias(ByteBuffer buffer) {

		StringBuilder name = new StringBuilder().append("");

		while (true) {
			boolean marked = false;
			byte b = buffer.get();

			if ((b & 0xC0) == 0xC0) {
				if (marked == false) {
					buffer.mark();
				}
				buffer.position(buffer.position() - 1);
				short offset = buffer.getShort();
				offset = (short) (offset & 0x3FFF);
				buffer.position(offset);
			} else if ((b == 0x00)) {
				if (marked == true) {
					buffer.reset();
				}
				return name.toString().substring(0, name.length() - 1);
			} else {
				int labelLength = b;
				addLabel(name, buffer, labelLength);

			}
		}

	}

	private static void addLabel(StringBuilder name, ByteBuffer buffer, int length) {
		for (int i = 0; i < length; i++) {
			name.append((char) buffer.get());
		}
		name.append(".");

	}

	private static String getIp(ByteBuffer buffer) {
		String ip = "";
		for (int i = 0; i < 4; i++) {
			ip.concat((Integer.toString((int) buffer.get())));
			if (!(i == 3)) {
				ip.concat(".");
			}
		}

		return ip;
	}

	private static void movePointer(ByteBuffer buffer) {

		while (true) {
			byte b = buffer.get();
			if ((b & 0xC0) == 0xC0) {
				buffer.get();
				return;
			}
			if ((b == 0x00)) {
				return;
			}
		}
	}

	private static DatagramPacket createRequest() {

		if (!printQuerySummary()) {
			return null;
		}

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
				clientSocket.close();

				long endTime = System.currentTimeMillis();
				double interval = (endTime - startTime) / 1000.0;

				System.out.println("Response received after " + interval + " seconds ( " + i + " retries )");

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

	private static boolean printQuerySummary() {
		String t = null;

		if (type == 1) {
			t = "A";
		} else if (type == 2) {
			t = "NS";
		} else if (type == 15) {
			t = "MX";
		} else {
			System.out.println("Unexpected Error");
			return false;
		}

		System.out.println("DnsClient sending request for " + name);
		System.out.println("Server: " + ipAddress);
		System.out.println("Request type: " + t);

		return true;

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
