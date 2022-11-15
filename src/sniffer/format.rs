use std::fmt::Display;

pub(crate) fn get_file_name(string: String) -> (String, String) {
    let mut string_md = string.trim().to_string();
    let mut string_xml = string.trim().to_string();

    if !string_md.ends_with(".md") {
        string_md.push_str(".md");
    }
    if !string_xml.ends_with(".xml") {
        string_xml.push_str(".xml");
    }
    (string_md, string_xml)
}

pub(crate) fn option_to_string<T: Display>(opt: Option<T>) -> String {
    match opt {
        Some(num) => num.to_string(),
        None => String::from("None")
    }
}

pub(crate) fn to_u16(p: &[u8], start: usize) -> u16 {
    let param1: u16 = p[start] as u16 * 256;
    let param2 = p[start + 1] as u16;
    param1 + param2
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_file_name_without_extensions() {
        let file_name = "file_name".to_string();
        let result = ("file_name.md".to_string(), "file_name.xml".to_string());
        assert_eq!(get_file_name(file_name), result);
    }

    #[test]
    fn test_file_name_ending_with_md() {
        let file_name = "file_namemd".to_string();
        let result = ("file_namemd.md".to_string(), "file_namemd.xml".to_string());
        assert_eq!(get_file_name(file_name), result);
    }

    #[test]
    fn test_file_name_ending_with_dot_md() {
        let file_name = "file_name.md".to_string();
        let result = ("file_name.md".to_string(), "file_name.md.xml".to_string());
        assert_eq!(get_file_name(file_name), result);
    }

    #[test]
    fn test_file_name_ending_with_xml() {
        let file_name = "file_namexml".to_string();
        let result = ("file_namexml.md".to_string(), "file_namexml.xml".to_string());
        assert_eq!(get_file_name(file_name), result);
    }

    #[test]
    fn test_file_name_ending_with_dot_xml() {
        let file_name = "file_name.xml".to_string();
        let result = ("file_name.xml.md".to_string(), "file_name.xml".to_string());
        assert_eq!(get_file_name(file_name), result);
    }

    #[test]
    fn test_opt_with_num_to_string() {
        let opt = Some(20);
        let result = "20".to_string();
        assert_eq!(option_to_string(opt), result);
    }

    #[test]
    fn test_opt_with_str_to_string() {
        let opt = Some("AAA");
        let result = "AAA".to_string();
        assert_eq!(option_to_string(opt), result);
    }

    #[test]
    fn test_opt_with_none_to_string() {
        let opt: Option<u8> = None;
        let result = "None".to_string();
        assert_eq!(option_to_string(opt), result);
    }

    #[test]
    fn test_zeros_to_u16() {
        let p = &[0, 0, 0];
        assert_eq!(to_u16(p, 0), 0);
    }

    #[test]
    fn test_max_num_to_u16() {
        let p = &[255, 255, 255];
        assert_eq!(to_u16(p, 0), 65535);
    }

    #[test]
    fn test_num_in_first_position_to_u16() {
        let p = &[1, 2, 3];
        assert_eq!(to_u16(p, 0), 258);
    }

    #[test]
    fn test_num_in_second_position_to_u16() {
        let p = &[1, 2, 3];
        assert_eq!(to_u16(p, 1), 515);
    }
}
