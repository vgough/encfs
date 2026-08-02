//! Helpers for driving a `PathFilesystem` directly, without a mounted
//! session. The runtime normally hands each operation the state belonging to
//! the node it addresses; tests have to resolve that state themselves.
//!
//! For an operation on an open file whose name is gone, build the reference
//! by hand instead: `PathNodeRef::new(None, node.state())`.
#![allow(dead_code)]

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use typed_fuse::{Caller, PathFilesystem, PathNodeRef};

/// A path together with the node state the runtime would pair with it.
pub struct Node<S> {
    path: PathBuf,
    state: Arc<S>,
}

impl<S> Node<S> {
    pub fn at(path: impl Into<PathBuf>, state: Arc<S>) -> Self {
        Self {
            path: path.into(),
            state,
        }
    }

    pub fn as_node(&self) -> PathNodeRef<'_, S> {
        PathNodeRef::new(Some(&self.path), &self.state)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn state(&self) -> &Arc<S> {
        &self.state
    }
}

impl<S> Clone for Node<S> {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            state: Arc::clone(&self.state),
        }
    }
}

/// Walks `path` from the root, returning the state of the final component.
/// Every component must exist.
pub fn resolve_state<P: PathFilesystem>(
    fs: &P,
    root: &Arc<P::NodeState>,
    path: &Path,
    caller: &Caller,
) -> Arc<P::NodeState> {
    let mut state = Arc::clone(root);
    let mut walked = if path.is_absolute() {
        PathBuf::from("/")
    } else {
        PathBuf::new()
    };
    for component in path.components() {
        let name = match component {
            Component::Normal(name) => name,
            Component::RootDir | Component::CurDir => continue,
            other => panic!("unsupported component {other:?} in {}", path.display()),
        };
        let parent = walked.clone();
        let entry = fs
            .lookup(PathNodeRef::new(Some(&parent), &state), name, caller)
            .unwrap_or_else(|error| panic!("lookup {name:?} in {}: {error}", parent.display()))
            .unwrap_or_else(|| panic!("{name:?} in {} does not exist", parent.display()));
        state = entry.state;
        walked.push(name);
    }
    state
}

/// [`resolve_state`] paired with the path it resolved.
pub fn node<P: PathFilesystem>(
    fs: &P,
    root: &Arc<P::NodeState>,
    path: impl AsRef<Path>,
    caller: &Caller,
) -> Node<P::NodeState> {
    let path = path.as_ref();
    Node::at(path, resolve_state(fs, root, path, caller))
}
