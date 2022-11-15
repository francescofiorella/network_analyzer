#[derive(Debug, Clone)]
pub enum NAState {
    RESUMED,
    PAUSED,
    STOPPED,
}

impl NAState {
    pub fn is_resumed(&self) -> bool {
        matches!(self, NAState::RESUMED)
    }
    pub fn is_paused(&self) -> bool {
        matches!(self, NAState::PAUSED)
    }
    pub fn is_stopped(&self) -> bool {
        matches!(self, NAState::STOPPED)
    }
}
