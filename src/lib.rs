use cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr};
use log::*;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

#[derive(Clone, PartialEq, Eq)]
pub struct IpRangeTreeNode {
    v4_ranges: Vec<Ipv4Cidr>,
    v6_ranges: Vec<Ipv6Cidr>,
    zero: Option<Box<IpRangeTreeNode>>,
    one: Option<Box<IpRangeTreeNode>>,
}

impl IpRangeTreeNode {
    pub fn new() -> Self {
        IpRangeTreeNode {
            v4_ranges: Vec::new(),
            v6_ranges: Vec::new(),
            zero: None,
            one: None,
        }
    }

    pub fn get_zero_mut(&mut self) -> Option<&mut Box<IpRangeTreeNode>> {
        self.zero.as_mut()
    }

    pub fn set_zero(&mut self, zero: Box<IpRangeTreeNode>) {
        self.zero = Some(zero);
    }

    pub fn get_one_mut(&mut self) -> Option<&mut Box<IpRangeTreeNode>> {
        self.one.as_mut()
    }

    pub fn set_one(&mut self, one: Box<IpRangeTreeNode>) {
        self.one = Some(one);
    }

    pub fn is_in_range_v4(&self, addr_binstr: &str, v4_addr: Ipv4Addr) -> bool {
        for cidr in self.v4_ranges.iter() {
            if cidr.contains(&v4_addr) {
                return true;
            }
        }
        if addr_binstr.len() == 0 {
            return false;
        }
        let (highest_bit, addr_binstr_rest) = addr_binstr.split_at(1);
        if highest_bit == "0" {
            if let Some(zero) = &self.zero {
                zero.is_in_range_v4(addr_binstr_rest, v4_addr)
            } else {
                false
            }
        } else {
            if let Some(one) = &self.one {
                one.is_in_range_v4(addr_binstr_rest, v4_addr)
            } else {
                false
            }
        }
    }

    pub fn is_in_range_v6(&self, addr_binstr: &str, v6_addr: Ipv6Addr) -> bool {
        for cidr in self.v6_ranges.iter() {
            if cidr.contains(&v6_addr) {
                return true;
            }
        }
        if addr_binstr.len() == 0 {
            return false;
        }
        let (highest_bit, addr_binstr_rest) = addr_binstr.split_at(1);
        if highest_bit == "0" {
            if let Some(zero) = &self.zero {
                zero.is_in_range_v6(addr_binstr_rest, v6_addr)
            } else {
                false
            }
        } else {
            if let Some(one) = &self.one {
                one.is_in_range_v6(addr_binstr_rest, v6_addr)
            } else {
                false
            }
        }
    }
}

pub struct IpRangeTree {
    root: IpRangeTreeNode,
}

impl IpRangeTree {
    pub fn new() -> Self {
        IpRangeTree {
            root: IpRangeTreeNode::new(),
        }
    }

    pub fn new_from_file(path: impl AsRef<str>) -> Result<Self, Box<dyn std::error::Error>> {
        let mut new_self = Self::new();

        let file_content = std::fs::read_to_string(path.as_ref()).unwrap();
        let lines = file_content.lines();

        for line in lines {
            let parts: Vec<&str> = line.split('/').collect();
            if parts.len() == 2 {
                let ip_addr_str = parts[0];
                let range_str = parts[1];
                if let Ok(range) = range_str.parse::<u8>() {
                    if let Ok(ipv6_addr) = Ipv6Addr::from_str(ip_addr_str) {
                        let v6_cidr = Ipv6Cidr::new(ipv6_addr, range)?;
                        let ip_cidr = IpCidr::V6(v6_cidr);
                        new_self.insert_range(ip_cidr)
                    } else if let Ok(ipv4_addr) = Ipv4Addr::from_str(ip_addr_str) {
                        let v4_cidr = Ipv4Cidr::new(ipv4_addr, range)?;
                        let ip_cidr = IpCidr::V4(v4_cidr);
                        new_self.insert_range(ip_cidr)
                    } else {
                        warn!(
                            "Failed to parse '{ip_addr_str}' of '{line}' into an IPv4 or IPv6 address"
                        )
                    }
                } else {
                    warn!("Failed to parse '{range_str}' of '{line}' into a u8")
                }
            }
        }

        Ok(new_self)
    }

    pub fn insert_v4_range(&mut self, v4_cidr: Ipv4Cidr) {
        let first_addr = v4_cidr.first_address();
        let addr_value = first_addr.to_bits();
        // -- get the binary representation of the address as a string with leading zeros
        let addr_binstr = Self::u32_to_binary_with_zeros(addr_value);
        debug!("Inserting v4 range {v4_cidr}, binary string is {addr_binstr}");
        // -- get the characters
        let mut bit_chars = addr_binstr.chars();
        let mut current = &mut self.root;
        for _ in 0..v4_cidr.network_length() {
            if let Some(bit_char) = bit_chars.next() {
                if bit_char == '0' {
                    debug!("{bit_char}");
                    current = if current.zero.is_some() {
                        match current.get_zero_mut() {
                            Some(zero) => zero,
                            _ => unreachable!(),
                        }
                    } else {
                        let zero = Box::new(IpRangeTreeNode::new());
                        current.set_zero(zero);
                        match current.get_zero_mut() {
                            Some(zero) => zero,
                            _ => unreachable!(),
                        }
                    };
                } else {
                    debug!("{bit_char}");
                    current = if current.one.is_some() {
                        match current.get_one_mut() {
                            Some(one) => one,
                            _ => unreachable!(),
                        }
                    } else {
                        let one = Box::new(IpRangeTreeNode::new());
                        current.set_one(one);
                        match current.get_one_mut() {
                            Some(one) => one,
                            _ => unreachable!(),
                        }
                    };
                }
            }
        }
        let mut found = false;
        for cidr in current.v4_ranges.iter_mut() {
            if cidr.first_address() == first_addr && cidr.last_address() == v4_cidr.last_address() {
                found = true;
                break;
            }
        }
        if !found {
            current.v4_ranges.push(v4_cidr);
        }
    }

    pub fn is_in_range_v4(&self, v4_addr: Ipv4Addr) -> bool {
        let addr_value = v4_addr.to_bits();
        // -- get the binary representation of the address as a string with leading zeros
        let addr_binstr = Self::u32_to_binary_with_zeros(addr_value);
        return self.root.is_in_range_v4(&addr_binstr, v4_addr);
    }

    pub fn is_in_range_v6(&self, v6_addr: Ipv6Addr) -> bool {
        let addr_value = v6_addr.to_bits();
        // -- get the binary representation of the address as a string with leading zeros
        let addr_binstr = Self::u128_to_binary_with_zeros(addr_value);
        return self.root.is_in_range_v6(&addr_binstr, v6_addr);
    }

    pub fn is_in_range(&self, ip_addr: IpAddr) -> bool {
        match ip_addr {
            IpAddr::V4(v4_addr) => self.is_in_range_v4(v4_addr),
            IpAddr::V6(v6_addr) => self.is_in_range_v6(v6_addr),
        }
    }

    pub fn insert_range(&mut self, ip_cidr: IpCidr) {
        // -- get network length and binary string representation of the address
        let (network_length, addr_binstr) = match ip_cidr {
            IpCidr::V4(v4_cidr) => {
                let first_addr = v4_cidr.first_address();
                let addr_value = first_addr.to_bits();
                // -- get the address as a string of '1' and '0' with leading zeros
                let addr_binstr = Self::u32_to_binary_with_zeros(addr_value);
                debug!("Inserting v4 range {v4_cidr}, binary string is {addr_binstr}");
                (v4_cidr.network_length(), addr_binstr)
            }
            IpCidr::V6(v6_cidr) => {
                let first_addr = v6_cidr.first_address();
                let addr_value = first_addr.to_bits();
                // -- get the address as a string of '1' and '0' with leading zeros
                let addr_binstr = Self::u128_to_binary_with_zeros(addr_value);
                debug!("Inserting v6 range {v6_cidr}, binary string is {addr_binstr}");
                (v6_cidr.network_length(), addr_binstr)
            }
        };

        // -- get the characters
        let mut bit_chars = addr_binstr.chars();
        let mut current = &mut self.root;
        // -- update the tree, insert tree nodes and eventually the CIDR
        for _ in 0..network_length {
            if let Some(bit_char) = bit_chars.next() {
                if bit_char == '0' {
                    debug!("{bit_char}");
                    current = if current.zero.is_some() {
                        match current.get_zero_mut() {
                            Some(zero) => zero,
                            _ => unreachable!(),
                        }
                    } else {
                        let zero = Box::new(IpRangeTreeNode::new());
                        current.set_zero(zero);
                        match current.get_zero_mut() {
                            Some(zero) => zero,
                            _ => unreachable!(),
                        }
                    };
                } else {
                    debug!("{bit_char}");
                    current = if current.one.is_some() {
                        match current.get_one_mut() {
                            Some(one) => one,
                            _ => unreachable!(),
                        }
                    } else {
                        let one = Box::new(IpRangeTreeNode::new());
                        current.set_one(one);
                        match current.get_one_mut() {
                            Some(one) => one,
                            _ => unreachable!(),
                        }
                    };
                }
            }
        }

        let mut found = false;
        if let IpCidr::V4(v4_cidr) = ip_cidr {
            for cidr in current.v4_ranges.iter_mut() {
                if cidr.first_address() == v4_cidr.first_address()
                    && cidr.last_address() == v4_cidr.last_address()
                {
                    found = true;
                    break;
                }
            }
            if !found {
                current.v4_ranges.push(v4_cidr);
            }
        } else if let IpCidr::V6(v6_cidr) = ip_cidr {
            for cidr in current.v6_ranges.iter_mut() {
                if cidr.first_address() == v6_cidr.first_address()
                    && cidr.last_address() == v6_cidr.last_address()
                {
                    found = true;
                    break;
                }
            }
            if !found {
                current.v6_ranges.push(v6_cidr);
            }
        }
    }

    fn u32_to_binary_with_zeros(decimal: u32) -> String {
        format!("{:0width$b}", decimal, width = 32)
    }

    fn u128_to_binary_with_zeros(decimal: u128) -> String {
        format!("{:0width$b}", decimal, width = 128)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_if_in_range() {
        // create range tree
        let mut ip_range_tree = IpRangeTree::new();

        // dding v4 ranges
        ip_range_tree.insert_range(IpCidr::V4(
            Ipv4Cidr::new(Ipv4Addr::new(192, 168, 40, 0), 24).expect("Failed to insert IPv4 range"),
        ));
        ip_range_tree.insert_range(IpCidr::V4(
            Ipv4Cidr::new(Ipv4Addr::new(192, 168, 41, 41), 32)
                .expect("Failed to insert IPv4 range"),
        ));
        ip_range_tree.insert_range(IpCidr::V4(
            Ipv4Cidr::new(Ipv4Addr::new(10, 0, 0, 0), 8).expect("Failed to insert IPv4 range"),
        ));
        ip_range_tree.insert_range(IpCidr::V4(
            Ipv4Cidr::new(Ipv4Addr::new(3, 24, 0, 0), 14).expect("Failed to insert IPv4 range"),
        ));

        // test v4 addresses
        let test_addr_v4 = Ipv4Addr::new(192, 168, 40, 55);
        let result = ip_range_tree.is_in_range_v4(test_addr_v4);
        assert_eq!(result, true);

        let test_addr = IpAddr::V4(test_addr_v4);
        let result = ip_range_tree.is_in_range(test_addr);
        assert_eq!(result, true);

        let test_addr_v4 = Ipv4Addr::new(192, 168, 41, 41);
        let result = ip_range_tree.is_in_range_v4(test_addr_v4);
        assert_eq!(result, true);

        let test_addr = IpAddr::V4(test_addr_v4);
        let result = ip_range_tree.is_in_range(test_addr);
        assert_eq!(result, true);

        let test_addr_v4 = Ipv4Addr::new(192, 168, 41, 42);
        let result = ip_range_tree.is_in_range_v4(test_addr_v4);
        assert_eq!(result, false);

        let test_addr = IpAddr::V4(test_addr_v4);
        let result = ip_range_tree.is_in_range(test_addr);
        assert_eq!(result, false);

        let test_addr_v4 = Ipv4Addr::new(10, 10, 10, 10);
        let result = ip_range_tree.is_in_range_v4(test_addr_v4);
        assert_eq!(result, true);

        let test_addr = IpAddr::V4(test_addr_v4);
        let result = ip_range_tree.is_in_range(test_addr);
        assert_eq!(result, true);

        let test_addr_v4 = Ipv4Addr::new(172, 17, 17, 17);
        let result = ip_range_tree.is_in_range_v4(test_addr_v4);
        assert_eq!(result, false);

        let test_addr = IpAddr::V4(test_addr_v4);
        let result = ip_range_tree.is_in_range(test_addr);
        assert_eq!(result, false);

        let test_addr_v4 = Ipv4Addr::new(3, 27, 203, 120);
        let result = ip_range_tree.is_in_range_v4(test_addr_v4);
        assert_eq!(result, true);

        let test_addr = IpAddr::V4(test_addr_v4);
        let result = ip_range_tree.is_in_range(test_addr);
        assert_eq!(result, true);

        // create tree from file
        let ip_range_tree = IpRangeTree::new_from_file("aws_ip_ranges.txt").unwrap();

        let test_addr_v4 = Ipv4Addr::new(3, 27, 203, 120);
        let result = ip_range_tree.is_in_range_v4(test_addr_v4);
        assert_eq!(result, true);

        let test_addr = IpAddr::V4(test_addr_v4);
        let result = ip_range_tree.is_in_range(test_addr);
        assert_eq!(result, true);

        let test_addr_v4 = Ipv4Addr::new(172, 17, 17, 17);
        let result = ip_range_tree.is_in_range_v4(test_addr_v4);
        assert_eq!(result, false);

        let test_addr = IpAddr::V4(test_addr_v4);
        let result = ip_range_tree.is_in_range(test_addr);
        assert_eq!(result, false);

        let test_addr_v6 = Ipv6Addr::new(0x2600, 0xf0f0, 0x5536, 1, 1, 1, 1, 1);
        let result = ip_range_tree.is_in_range_v6(test_addr_v6);
        assert_eq!(result, true);

        let test_addr = IpAddr::V6(test_addr_v6);
        let result = ip_range_tree.is_in_range(test_addr);
        assert_eq!(result, true);

        let test_addr_v6 = Ipv6Addr::new(0x2601, 0xf0f0, 0x5536, 1, 1, 1, 1, 1);
        let result = ip_range_tree.is_in_range_v6(test_addr_v6);
        assert_eq!(result, false);

        let test_addr = IpAddr::V6(test_addr_v6);
        let result = ip_range_tree.is_in_range(test_addr);
        assert_eq!(result, false);
    }
}
