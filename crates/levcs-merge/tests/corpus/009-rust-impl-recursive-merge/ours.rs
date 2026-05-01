struct Page;

impl Page {
    fn render(&self) -> String {
        String::new()
    }
    fn cache_key(&self) -> u64 {
        0
    }
}
