use slab::Slab;

use crate::Inode;

#[derive(Debug)]
pub struct InodeGenerator {
    slab: Slab<()>,
}

impl InodeGenerator {
    pub fn new() -> Self {
        let mut slab = Slab::new();
        // drop 0 key
        slab.insert(());

        Self { slab }
    }

    pub fn allocate_inode(&mut self) -> Inode {
        self.slab.insert(()) as _
    }

    pub fn release_inode(&mut self, inode: Inode) {
        if self.slab.contains(inode as _) {
            self.slab.remove(inode as _);
        }
    }
}
