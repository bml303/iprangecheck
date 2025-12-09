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

There is also a more comprehensive source of IP ranges available from [public-cloud-provider-ip-ranges](https://github.com/tobilg/public-cloud-provider-ip-ranges). To generate a file with all the IP ranges, run:

```shell
curl -o all.json https://raw.githubusercontent.com/tobilg/public-cloud-provider-ip-ranges/main/data/providers/all.json
jq -r '.[] | select(.cidr_block) | .cidr_block' all.json > all_ip_ranges.txt
```

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
iprangecheck = { git = "https://github.com/bml303/iprangecheck.git" }
```
