//! Kills a Linux plugin process tree from the live broker.
//!
//! `kill_on_drop` signals only the outer bubblewrap process. Cancellation drops
//! this guard first, while `/proc` still lists the sandboxed children.

use std::fs;

pub(super) struct KillPluginTree {
    pid: u32,
    armed: bool,
}

impl KillPluginTree {
    pub(super) fn arm(pid: u32) -> Self {
        Self { pid, armed: true }
    }

    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }

    pub(super) fn finish(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        kill_plugin_tree(self.pid);
    }
}

impl Drop for KillPluginTree {
    fn drop(&mut self) {
        self.finish();
    }
}

fn kill_plugin_tree(pid: u32) {
    let mut pending = vec![pid];
    let mut seen = vec![pid];
    while let Some(current) = pending.pop() {
        for child in direct_children(current) {
            if seen.contains(&child) {
                continue;
            }
            seen.push(child);
            pending.push(child);
        }
    }
    for pid in seen.iter().rev().copied() {
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    }
    unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
}

fn direct_children(pid: u32) -> Vec<u32> {
    let mut children = Vec::new();
    let Ok(tasks) = fs::read_dir(format!("/proc/{pid}/task")) else {
        return children;
    };
    for task in tasks.flatten() {
        let Ok(text) = fs::read_to_string(task.path().join("children")) else {
            continue;
        };
        for value in text.split_whitespace() {
            if let Ok(child) = value.parse::<u32>() {
                children.push(child);
            }
        }
    }
    children
}
