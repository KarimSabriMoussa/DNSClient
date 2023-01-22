import java.util.ArrayList;
import java.util.Arrays;
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

		System.out.println(timeout);
		System.out.println(retries);
		System.out.println(port);
		System.out.println(type);
		System.out.println(ipAddress);
		System.out.println(name);

	}

	private static void parse(String[] args) {
		ArrayList<String> argList = new ArrayList<String>(Arrays.asList(args));

		int i = argList.indexOf("-t");
		if (i != -1) {
			if (isInteger(argList.get(i + 1))) {
				timeout = Integer.parseInt(argList.get(i + 1));
			}else{
                displayUsage();
            }
		}

		i = argList.indexOf("-r");
		if (i != -1) {
			if (isInteger(argList.get(i + 1))) {
				retries = Integer.parseInt(argList.get(i + 1));
			}else{
                displayUsage();
            }
		}

		i = argList.indexOf("-p");
		if (i != -1) {
			if (isInteger(argList.get(i + 1))) {
				port = Integer.parseInt(argList.get(i + 1));
			}else{
                displayUsage();
            }
		}

		i = argList.indexOf("-ns");
		if (i != -1) {
			if (type == 1) {
				type = 2;
			}else{
                displayUsage();
            }
		}

		i = argList.indexOf("-mx");
		if (i != -1) {
			if (type == 1) {
				type = 15;
			}else{
                displayUsage();
            }
		}



		String server = argList.get(argList.size() - 2);
		if (server.startsWith("@")) {
			ipAddress = server.substring(1);
		}else{
            displayUsage();
        }

		String domainRegex = "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z]{2,6}";

		Pattern domainPattern = Pattern.compile(domainRegex);

		String domainName = argList.get(argList.size() - 1);
		Matcher domainMatcher = domainPattern.matcher(domainName);
		if (domainMatcher.matches()) {
			name = domainName;
		}else{
            displayUsage();
        }

	}

    private static void displayUsage(){
        System.out.println("Invalid Input");
        System.out.println("Proper Usage: java DnsClient [-t timeout] [-r max-retries] [-p port] [-mx|-ns] @server name");
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
