[![progress-banner](https://backend.codecrafters.io/progress/dns-server/db9dd43e-f6cf-4c96-9355-82220aba136b)](https://app.codecrafters.io/users/codecrafters-bot?r=2qF)

the codecrafters.io "Build Your Own DNS Server" challenge


# Usage
`cargo r --resolver <address>`
<address> is in the format `ip:port`
it is the ip of the DNS server to forward queris to

any query sent to this running without a resolver address will get a default `8.8.8.8` response.
As this doesn't have any implementation for iptables or anything like that.
