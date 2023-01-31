# DNSClient
 Usage: java DnsClient [-r i] [-t j] [-p k] [-ns|-mx] @ServerIP DomainName\n
 All the switches between square brackets are optional. If you incluse -r,-t or -p they must be followed by a value.\n
Minimum acceptable values:
* i: 1
* j: 0.001
* k: 0
 The switches -ns and -mx are mutually exclusive.\n
 The switches can appear in any order as arguments between the program name and the @ServerIP.\n
 The ServerIP must be the argument before the last when running the program.\n
 The DomainName must be the last argument when running the program.\n
