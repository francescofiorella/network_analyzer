use network_analyzer::sniffer::format::get_file_name;

#[test]
fn file_name_without_extensions() {
    let file_name = "file_name".to_string();
    let result = ("file_name.md".to_string(), "file_name.xml".to_string());
    assert_eq!(get_file_name(file_name), result);
}

#[test]
fn file_name_ending_with_md() {
    let file_name = "file_namemd".to_string();
    let result = ("file_namemd.md".to_string(), "file_namemd.xml".to_string());
    assert_eq!(get_file_name(file_name), result);
}

#[test]
fn file_name_ending_with_dot_md() {
    let file_name = "file_name.md".to_string();
    let result = ("file_name.md".to_string(), "file_name.md.xml".to_string());
    assert_eq!(get_file_name(file_name), result);
}

#[test]
fn file_name_ending_with_xml() {
    let file_name = "file_namexml".to_string();
    let result = ("file_namexml.md".to_string(), "file_namexml.xml".to_string());
    assert_eq!(get_file_name(file_name), result);
}

#[test]
fn file_name_ending_with_dot_xml() {
    let file_name = "file_name.xml".to_string();
    let result = ("file_name.xml.md".to_string(), "file_name.xml".to_string());
    assert_eq!(get_file_name(file_name), result);
}
