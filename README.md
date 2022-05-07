# ECSE_316
Small dns client which can ping servers to get the ns records, mx, records etc. 

## Usage

CLI Argument | Short |Optional | Description |
--- | --- | --- | --- | 
--timeout | -t | T | Timeout: How long to wait, in seconds, before retransmitting an unanswered query. Default value: 5 |
--maxrepeat | -r | T | Max retries: The maximum number of times to retransmit an unanswered query before giving up. Default value: 3 |
--port | -p | T | The UDP port number of the DNS server. Default value: 53 |
-mx | N/A | T | Indicate whether to send a MX (mail server) or NS (name server) query. At most one of these can be given, and if neither is given then the client should send a type A (IP address) query |
-ns | N/A | T | Indicate whether to send a NS (mail server) or NS (name server) query. At most one of these can be given, and if neither is given then the client should send a type A (IP address) query |
N/A (positional argument)| N/A | F | Server: the IPv4 address of the DNS server, in @a.b.c.d. format |
N/A (positional argument)| N/A | F | Name: the domain name to query for |
