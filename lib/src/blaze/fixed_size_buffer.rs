use std::usize;

pub(crate) struct FixedSizeBuffer<T> {
    buf: Vec<T>,
    pos: usize,
    capacity: usize,
}

impl<T> FixedSizeBuffer<T> {
    pub fn new(capacity: usize) -> Self {
        if capacity == 0 {
            panic!("Capacity should be at least 1");
        }

        let mut buf = Vec::<T>::new();
        buf.reserve_exact(capacity);
        Self { buf, pos: 0, capacity }
    }

    pub fn push(&mut self, item: T) {
        if self.buf.len() == self.capacity {
            self.buf[self.pos] = item;
        } else {
            self.buf.push(item);
        }
        self.pos = (self.pos + 1) % self.capacity;
    }

    pub fn into_vec(mut self) -> Vec<T> {
        let right = self.buf.split_off(self.pos);

        let mut v = vec![];
        v.extend(right);
        v.extend(self.buf);

        v
    }
}

#[cfg(test)]
mod test {
    use super::FixedSizeBuffer;

    #[test]
    fn test_basic() {
        let mut b = FixedSizeBuffer::new(5);
        for i in 0..5 {
            b.push(i);
        }
        assert_eq!(b.into_vec(), (0..5).collect::<Vec<_>>());
    }

    #[test]
    fn test_extra_even() {
        let mut b = FixedSizeBuffer::new(5);
        for i in 0..15 {
            b.push(i);
        }
        assert_eq!(b.into_vec(), (10..15).collect::<Vec<_>>());
    }

    #[test]
    fn test_extra_odd() {
        let mut b = FixedSizeBuffer::new(5);
        for i in 0..13 {
            b.push(i);
        }
        assert_eq!(b.into_vec(), (8..13).collect::<Vec<_>>());
    }

    #[test]
    fn test_under() {
        let mut b = FixedSizeBuffer::new(5);
        for i in 0..3 {
            b.push(i);
        }
        assert_eq!(b.into_vec(), (0..3).collect::<Vec<_>>());
    }

    #[test]
    fn test_empty() {
        let b = FixedSizeBuffer::<u64>::new(5);
        assert_eq!(b.into_vec(), Vec::<u64>::new());
    }

    #[test]
    #[should_panic]
    fn test_0cap() {
        let _b = FixedSizeBuffer::<u64>::new(0);
    }
}
