use crate::sniffer::na_error::NAError;

/// Enumerates the different filtering categories offered by the network_analyzer library.
/// It also implements the `ToString` trait, allowing a correct transformation of `Filter`'s
/// tag (and possible detail) into a proper string representation.
///
/// <br></br>
/// <i> Example </i>
/// * `Filter::IP(192.168.1.1)` is converted into "IP 192.168.1.1"
/// * `Filter::Port(443)` is converted into "port 443"
#[derive(Clone, Debug, PartialEq)]
pub enum Filter {
    None,
    IPv4,
    IPv6,
    ARP,
    IP(String),
    Port(u16),
    LT(u32),
    LE(u32),
    EQ(u32),
    GT(u32),
    GE(u32),
}

impl ToString for Filter {
    fn to_string(&self) -> String {
        match self {
            Filter::None => "None".to_string(),
            Filter::IPv4 => "IPv4".to_string(),
            Filter::IPv6 => "IPv6".to_string(),
            Filter::ARP => "ARP".to_string(),
            Filter::IP(ip) => ("IP ".to_owned() + ip).to_string(),
            Filter::Port(port) => {
                let mut s = String::from("port ");
                s.push_str(&port.to_string());
                s
            }
            Filter::LT(len) => ("length < ".to_owned() + len.to_string().as_str()).to_string(),
            Filter::LE(len) => ("length <= ".to_owned() + len.to_string().as_str()).to_string(),
            Filter::EQ(len) => ("length = ".to_owned() + len.to_string().as_str()).to_string(),
            Filter::GT(len) => ("length > ".to_owned() + len.to_string().as_str()).to_string(),
            Filter::GE(len) => ("length >= ".to_owned() + len.to_string().as_str()).to_string(),
        }
    }
}

///Associates a received string to a `Filter` (if possible), or returns an `NAError`
///
///This function associates a string to a filter, by analyzing the correctness of the
///passed parameter.
///
/// <br></br>
///<i>Example</i>:
///* "ipv4" can be associated to a `Filter::IPv4` filter
///* "192.168.1.1" can be associated to  `Filter::IP(String)`
///* "2001:db8::2:1" can be associated to a `Filter::IP(String)`
///* "foo.192 foo" cannot be associated to any filter
/// * ">=1514" can be associated to a `Filter::GE(u16)`.
///
///  Can raise errors:
/// - ⚠ **Not a valid IPv4 addr. as filter**: filter parameter contains values that cannot be parsed as u8
/// - ⚠ **Not an IP addr. as filter**: filter parameter doesn't contain a well formatted IP address (no separation dots or wrong length)
/// - ⚠ **Not a valid IPv6 addr. as filter**: filter parameter contains values that cannot be parsed as u16 or doesn't represent a well formatted address (no separation points or wrong length)
/// - ⚠ **Not a valid packet length**: filter parameter contains values that cannot be parsed as u32
/// - ⚠ **Unavailable filter**: filter parameter doesn't contain a valid value (accepted values are: "none","ipv4","ipv6","arp",ipv4 address, ipv6 address, `[<=,>=,<,>,=]`[u32])

pub fn get_filter(filter: &String) -> Result<Filter, NAError> {
    //Actually available filters
    let f = filter.as_str();
    match f {
        "none" => Ok(Filter::None),
        "ipv4" => Ok(Filter::IPv4),
        "ipv6" => Ok(Filter::IPv6),
        "arp" => Ok(Filter::ARP),

        //ipv4 addr
        string if string.contains('.') => {
            let v: Vec<&str> = string.split('.').collect();
            if v.len() == 4 {
                for u8_block in v {
                    if u8_block.parse::<u8>().is_err() {
                        return Err(NAError::new("Not a valid IPv4 addr. as filter"));
                    }
                }
                return Ok(Filter::IP(string.to_string()));
            }
            return Err(NAError::new("Not an IP addr. as filter"));
        }

        //ipv6 addr
        string if string.contains(':') => {
            let v: Vec<&str> = string.split(':').collect();
            if v.len() <= 8 {
                for u16_block in v {
                    if u16::from_str_radix(u16_block, 16).is_err() && !u16_block.is_empty() {
                        return Err(NAError::new("Not a valid IPv6 addr. as filter"));
                    }
                }
                return Ok(Filter::IP(string.to_string()));
            }
            return Err(NAError::new("Not a valid IPv6 addr. as filter"));
        }

        //port
        string if string.parse::<u16>().is_ok() => Ok(Filter::Port(string.parse::<u16>().unwrap())),

        //length (le)
        string if string.starts_with("<=") => {
            let mut string = string.to_string();
            string.remove(0);
            string.remove(0);
            match string.parse::<u32>() {
                Err(_) => Err(NAError::new("Not a valid packet length")),
                Ok(len) => Ok(Filter::LE(len))
            }
        }

        //length (ge)
        string if string.starts_with(">=") => {
            let mut string = string.to_string();
            string.remove(0);
            string.remove(0);
            match string.parse::<u32>() {
                Err(_) => Err(NAError::new("Not a valid packet length")),
                Ok(len) => Ok(Filter::GE(len))
            }
        }

        //length (eq)
        string if string.starts_with("=") => {
            let mut string = string.to_string();
            string.remove(0);
            match string.parse::<u32>() {
                Err(_) => Err(NAError::new("Not a valid packet length")),
                Ok(len) => Ok(Filter::EQ(len))
            }
        }
        //length (gt)
        string if string.starts_with(">") => {
            let mut string = string.to_string();
            string.remove(0);
            match string.parse::<u32>() {
                Err(_) => Err(NAError::new("Not a valid packet length")),
                Ok(len) => Ok(Filter::GT(len))
            }
        }

        //length (lt)
        string if string.starts_with("<") => {
            let mut string = string.to_string();
            string.remove(0);
            match string.parse::<u32>() {
                Err(_) => Err(NAError::new("Not a valid packet length")),
                Ok(len) => Ok(Filter::LT(len))
            }
        }

        _ => Err(NAError::new("Unavailable filter")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_none_filter() {
        let filter_name = "none".to_string();
        assert_eq!(get_filter(&filter_name).unwrap(), Filter::None);
    }

    #[test]
    fn test_ipv4_filter() {
        let filter_name = "ipv4".to_string();
        assert_eq!(get_filter(&filter_name).unwrap(), Filter::IPv4);
    }

    #[test]
    fn test_ipv6_filter() {
        let filter_name = "ipv6".to_string();
        assert_eq!(get_filter(&filter_name).unwrap(), Filter::IPv6);
    }

    #[test]
    fn test_arp_filter() {
        let filter_name = "arp".to_string();
        assert_eq!(get_filter(&filter_name).unwrap(), Filter::ARP);
    }

    #[test]
    fn test_correct_ipv4_filter() {
        let filter_name = "192.168.1.5".to_string();
        assert_eq!(get_filter(&filter_name).unwrap(), Filter::IP(filter_name));
    }

    #[test]
    #[should_panic(expected = "Not an IP addr. as filter")]
    fn test_short_ipv4_filter() {
        let filter_name = "192.168.1".to_string();
        get_filter(&filter_name).unwrap();
    }

    #[test]
    #[should_panic(expected = "Not a valid IPv4 addr. as filter")]
    fn test_not_parsable1_ipv4_filter() {
        let filter_name = "192.foo.1.2".to_string();
        get_filter(&filter_name).unwrap();
    }

    #[test]
    #[should_panic(expected = "Not a valid IPv4 addr. as filter")]
    fn test_not_parsable2_ipv4_filter() {
        let filter_name = "192.256.1.2".to_string();
        get_filter(&filter_name).unwrap();
    }

    #[test]
    fn test_correct_ipv6_filter() {
        let filter_name = "2001:db8::2:1".to_string();
        assert_eq!(get_filter(&filter_name).unwrap(), Filter::IP(filter_name));
    }

    #[test]
    #[should_panic(expected = "Not a valid IPv6 addr. as filter")]
    fn test_long_ipv6_filter() {
        let filter_name = "2001:db8::2:1::ab::fe:".to_string();
        get_filter(&filter_name).unwrap();
    }

    #[test]
    #[should_panic(expected = "Not a valid IPv6 addr. as filter")]
    fn test_not_parsable1_ipv6_filter() {
        let filter_name = "2001:foo::".to_string();
        get_filter(&filter_name).unwrap();
    }

    #[test]
    fn test_biggest_ipv6_filter() {
        let filter_name = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".to_string();
        assert_eq!(get_filter(&filter_name).unwrap(), Filter::IP(filter_name));
    }

    #[test]
    #[should_panic(expected = "Not a valid IPv6 addr. as filter")]
    fn test_not_parsable2_ipv6_filter() {
        let filter_name = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff1".to_string();
        get_filter(&filter_name).unwrap();
    }

    #[test]
    fn test_correct_port_filter() {
        let filter_name = "8080".to_string();
        assert_eq!(get_filter(&filter_name).unwrap(), Filter::Port(8080));
    }

    #[test]
    fn test_last_u16_parsable_port_number() {
        let filter_name = "65535".to_string();
        assert_eq!(get_filter(&filter_name).unwrap(), Filter::Port(65535));
    }

    #[test]
    fn test_0_port_number() {
        let filter_name = "0".to_string();
        assert_eq!(get_filter(&filter_name).unwrap(), Filter::Port(0));
    }

    #[test]
    #[should_panic(expected = "Unavailable filter")]
    fn test_not_u16_parsable_port_number() {
        let filter_name = "65536".to_string();
        get_filter(&filter_name).unwrap();
    }

    #[test]
    #[should_panic(expected = "Unavailable filter")]
    fn test_negative_port_number() {
        let filter_name = "-1".to_string();
        get_filter(&filter_name).unwrap();
    }

    #[test]
    fn test_lt_filter() {
        let filter_name = "<65535".to_string();
        assert_eq!(get_filter(&filter_name).unwrap(), Filter::LT(65535));
    }

    #[test]
    fn test_0_lt_filter() {
        let filter_name = "<0".to_string();
        assert_eq!(get_filter(&filter_name).unwrap(), Filter::LT(0));
    }

    #[test]
    #[should_panic(expected = "Not a valid packet length")]
    fn test_wrong_lt_spaced_filter() {
        let filter_name = "< 65535".to_string();
        get_filter(&filter_name).unwrap();
    }

    #[test]
    #[should_panic(expected = "Not a valid packet length")]
    fn test_negative_lt_filter() {
        let filter_name = "<-1".to_string();
        get_filter(&filter_name).unwrap();
    }

    #[test]
    #[should_panic(expected = "Not a valid packet length")]
    fn test_unparsable_lt_filter() {
        let filter_name = "<foo".to_string();
        get_filter(&filter_name).unwrap();
    }

    #[test]
    fn test_le_filter() {
        let filter_name = "<=65535".to_string();
        assert_eq!(get_filter(&filter_name).unwrap(), Filter::LE(65535));
    }

    #[test]
    fn test_0_le_filter() {
        let filter_name = "<=0".to_string();
        assert_eq!(get_filter(&filter_name).unwrap(), Filter::LE(0));
    }

    #[test]
    #[should_panic(expected = "Not a valid packet length")]
    fn test_wrong_le_spaced_filter() {
        let filter_name = "<= 65535".to_string();
        get_filter(&filter_name).unwrap();
    }

    #[test]
    #[should_panic(expected = "Not a valid packet length")]
    fn test_negative_le_filter() {
        let filter_name = "<=-1".to_string();
        get_filter(&filter_name).unwrap();
    }

    #[test]
    #[should_panic(expected = "Not a valid packet length")]
    fn test_unparsable_le_filter() {
        let filter_name = "<=foo".to_string();
        get_filter(&filter_name).unwrap();
    }

    #[test]
    fn test_eq_filter() {
        let filter_name = "=65535".to_string();
        assert_eq!(get_filter(&filter_name).unwrap(), Filter::EQ(65535));
    }

    #[test]
    fn test_0_eq_filter() {
        let filter_name = "=0".to_string();
        assert_eq!(get_filter(&filter_name).unwrap(), Filter::EQ(0));
    }

    #[test]
    #[should_panic(expected = "Not a valid packet length")]
    fn test_wrong_eq_spaced_filter() {
        let filter_name = "= 65535".to_string();
        get_filter(&filter_name).unwrap();
    }

    #[test]
    #[should_panic(expected = "Not a valid packet length")]
    fn test_negative_eq_filter() {
        let filter_name = "=-1".to_string();
        get_filter(&filter_name).unwrap();
    }

    #[test]
    #[should_panic(expected = "Not a valid packet length")]
    fn test_unparsable_eq_filter() {
        let filter_name = "=foo".to_string();
        get_filter(&filter_name).unwrap();
    }

    #[test]
    fn test_ge_filter() {
        let filter_name = ">=65535".to_string();
        assert_eq!(get_filter(&filter_name).unwrap(), Filter::GE(65535));
    }

    #[test]
    fn test_0_ge_filter() {
        let filter_name = ">=0".to_string();
        assert_eq!(get_filter(&filter_name).unwrap(), Filter::GE(0));
    }

    #[test]
    #[should_panic(expected = "Not a valid packet length")]
    fn test_wrong_ge_spaced_filter() {
        let filter_name = ">= 65535".to_string();
        get_filter(&filter_name).unwrap();
    }

    #[test]
    #[should_panic(expected = "Not a valid packet length")]
    fn test_negative_ge_filter() {
        let filter_name = ">=-1".to_string();
        get_filter(&filter_name).unwrap();
    }

    #[test]
    #[should_panic(expected = "Not a valid packet length")]
    fn test_unparsable_ge_filter() {
        let filter_name = ">=foo".to_string();
        get_filter(&filter_name).unwrap();
    }

    #[test]
    fn test_gt_filter() {
        let filter_name = ">65535".to_string();
        assert_eq!(get_filter(&filter_name).unwrap(), Filter::GT(65535));
    }

    #[test]
    fn test_0_gt_filter() {
        let filter_name = ">0".to_string();
        assert_eq!(get_filter(&filter_name).unwrap(), Filter::GT(0));
    }

    #[test]
    #[should_panic(expected = "Not a valid packet length")]
    fn test_wrong_gt_spaced_filter() {
        let filter_name = "> 65535".to_string();
        get_filter(&filter_name).unwrap();
    }

    #[test]
    #[should_panic(expected = "Not a valid packet length")]
    fn test_negative_gt_filter() {
        let filter_name = ">-1".to_string();
        get_filter(&filter_name).unwrap();
    }

    #[test]
    #[should_panic(expected = "Not a valid packet length")]
    fn test_unparsable_gt_filter() {
        let filter_name = ">foo".to_string();
        get_filter(&filter_name).unwrap();
    }
}
