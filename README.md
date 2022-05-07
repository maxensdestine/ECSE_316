# ECSE_316
This project is a small dns client which was made during the 2022 Winter semeter for the course ECSE 316. This CLI app can ping servers to get the ns records, mx, records etc. 

### Authors
Ada Andrei and Maxens Destiné

## Usage

CLI Argument | Short |Optional | Description |
--- | --- | --- | --- | 
--timeout | -t | True | Timeout: How long to wait, in seconds, before retransmitting an unanswered query. Default value: 5 |
--maxrepeat | -r | True | Max retries: The maximum number of times to retransmit an unanswered query before giving up. Default value: 3 |
--port | -p | True | The UDP port number of the DNS server. Default value: 53 |
-mx | N/A | True | Indicate whether to send a MX (mail server) or NS (name server) query. At most one of these can be given, and if neither is given then the client should send a type A (IP address) query |
-ns | N/A | True | Indicate whether to send a NS (mail server) or NS (name server) query. At most one of these can be given, and if neither is given then the client should send a type A (IP address) query |
N/A (positional argument)| N/A | False | Server: the IPv4 address of the DNS server, in @a.b.c.d. format |
N/A (positional argument)| N/A | False | Name: the domain name to query for |
