# iprangecheck

## Generate file with ip ranges

For the sake of this example we assume that all the AWS IP ranges are to be checked. First download the AWS IP ranges file from https://ip-ranges.amazonaws.com/ip-ranges.json and save it as `aws_ip_ranges.json`:

```shell
curl -o aws_ip_ranges.json https://ip-ranges.amazonaws.com/ip-ranges.json
```

Then extract all the IPv4 ranges into a text file with one IP range per line:

```shell
jq -r '.prefixes[] | select(.ip_prefix) | .ip_prefix' aws_ip_ranges.json > aws_ip_ranges.txt
```

Append the IPv6 ranges to the same file:

```shell
jq -r '.ipv6_prefixes[] | select(.ipv6_prefix) | .ipv6_prefix' aws_ip_ranges.json >> aws_ip_ranges.txt
```

## Usage
