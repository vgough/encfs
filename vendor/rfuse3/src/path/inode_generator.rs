use crate::Inode;

#[derive(Debug)]
pub struct InodeGenerator {
    next_inode: Inode,
}

impl InodeGenerator {
    pub fn new() -> Self {
        Self { next_inode: 1 }
    }

    pub fn allocate_inode(&mut self) -> Inode {
        let inode = self.next_inode;
        self.next_inode = self
            .next_inode
            .checked_add(1)
            .expect("FUSE inode number space exhausted");
        inode
    }

    /// Node IDs are deliberately not reused during a mount. The kernel may retain
    /// cached references until a later FORGET, and generation zero cannot safely
    /// distinguish an eagerly recycled ID from its previous object.
    pub fn release_inode(&mut self, _inode: Inode) {}
}
