//! End-to-end cumulative acknowledgements over authenticated onion cells.
//! A peer cannot grant credit for data that was never sent.
pub const WINDOW_CELLS: u32 = 32;
#[derive(Default)]
pub struct SendWindow {
    sent: u32,
    acknowledged: u32,
}
impl SendWindow {
    pub fn drained(&self) -> bool {
        self.sent == self.acknowledged
    }
    pub fn available(&self) -> bool {
        self.sent - self.acknowledged < WINDOW_CELLS
    }
    pub fn sent(&mut self) -> Result<(), &'static str> {
        if !self.available() {
            return Err("Data window exhausted");
        }
        self.sent = self.sent.checked_add(1).ok_or("Data counter exhausted")?;
        Ok(())
    }
    pub fn acknowledge(&mut self, payload: &[u8]) -> Result<(), &'static str> {
        let value = u32::from_be_bytes(
            payload
                .try_into()
                .map_err(|_| "Invalid acknowledgement size")?,
        );
        if value <= self.acknowledged || value > self.sent {
            return Err("Invalid or replayed acknowledgement");
        }
        self.acknowledged = value;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authenticated_credit_is_bounded() {
        let mut window = SendWindow::default();
        for _ in 0..WINDOW_CELLS {
            window.sent().unwrap();
        }
        assert!(!window.available());
        assert!(window.sent().is_err());
        assert!(window
            .acknowledge(&(WINDOW_CELLS + 1).to_be_bytes())
            .is_err());
        window.acknowledge(&16u32.to_be_bytes()).unwrap();
        assert!(window.available());
        assert!(window.acknowledge(&16u32.to_be_bytes()).is_err());
        assert!(window.acknowledge(&[0; 3]).is_err());
    }
}
