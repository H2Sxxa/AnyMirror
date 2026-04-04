use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};

use crate::rules::matcher::path_has_prefix;

#[derive(Debug, Clone, Default)]
pub(super) struct PrefixPathTrie {
    root: PrefixPathNode,
}

#[derive(Debug, Clone, Default)]
struct PrefixPathNode {
    children: HashMap<u8, PrefixPathNode>,
    terminals: Vec<PrefixTerminal>,
}

#[derive(Debug, Clone)]
struct PrefixTerminal {
    index: usize,
    path: String,
}

#[derive(Debug, Clone, Default)]
pub(super) struct HostSuffixTrie {
    root: HostSuffixNode,
}

#[derive(Debug, Clone, Default)]
struct HostSuffixNode {
    children: HashMap<String, HostSuffixNode>,
    terminal_indices: Vec<usize>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct DnsSuffixTrie {
    root: DnsSuffixNode,
}

#[derive(Debug, Clone, Default)]
struct DnsSuffixNode {
    children: HashMap<String, DnsSuffixNode>,
    terminal: bool,
}

#[derive(Debug, Clone, Default)]
pub(super) struct Ipv4CidrTrie {
    root: Ipv4CidrNode,
}

#[derive(Debug, Clone, Default)]
struct Ipv4CidrNode {
    zero: Option<Box<Ipv4CidrNode>>,
    one: Option<Box<Ipv4CidrNode>>,
    terminal_indices: Vec<usize>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct Ipv6CidrTrie {
    root: Ipv6CidrNode,
}

#[derive(Debug, Clone, Default)]
struct Ipv6CidrNode {
    zero: Option<Box<Ipv6CidrNode>>,
    one: Option<Box<Ipv6CidrNode>>,
    terminal_indices: Vec<usize>,
}

impl PrefixPathTrie {
    pub(super) fn insert(&mut self, path: &str, index: usize) {
        let mut node = &mut self.root;
        for byte in path.bytes() {
            node = node.children.entry(byte).or_default();
        }
        node.terminals.push(PrefixTerminal {
            index,
            path: path.to_string(),
        });
    }

    pub(super) fn visit_matches<F>(&self, path: &str, mut visitor: F)
    where
        F: FnMut(usize),
    {
        let mut node = &self.root;
        for byte in path.bytes() {
            let Some(next) = node.children.get(&byte) else {
                return;
            };
            node = next;
            for terminal in &node.terminals {
                if path_has_prefix(path, &terminal.path) {
                    visitor(terminal.index);
                }
            }
        }
    }
}

impl HostSuffixTrie {
    pub(super) fn insert(&mut self, suffix: &str, index: usize) {
        let mut node = &mut self.root;
        for label in suffix.rsplit('.') {
            node = node.children.entry(label.to_string()).or_default();
        }
        node.terminal_indices.push(index);
    }

    pub(super) fn visit_matches<F>(&self, host: &str, mut visitor: F)
    where
        F: FnMut(usize),
    {
        let mut node = &self.root;
        for label in host.rsplit('.') {
            let Some(next) = node.children.get(label) else {
                return;
            };
            node = next;
            for index in &node.terminal_indices {
                visitor(*index);
            }
        }
    }
}

impl DnsSuffixTrie {
    pub(super) fn insert(&mut self, suffix: &str) {
        let mut node = &mut self.root;
        for label in suffix.rsplit('.') {
            node = node.children.entry(label.to_string()).or_default();
        }
        node.terminal = true;
    }

    pub(super) fn matches(&self, host: &str) -> bool {
        let mut node = &self.root;
        for label in host.rsplit('.') {
            let Some(next) = node.children.get(label) else {
                return false;
            };
            node = next;
            if node.terminal {
                return true;
            }
        }
        false
    }
}

impl Ipv4CidrTrie {
    pub(super) fn insert(&mut self, cidr: Ipv4Net, index: usize) {
        let mut node = &mut self.root;
        let bits = u32::from(cidr.network());
        for depth in 0..cidr.prefix_len() {
            let bit = bit_u32(bits, depth);
            node = if bit {
                node.one.get_or_insert_with(Box::<Ipv4CidrNode>::default)
            } else {
                node.zero.get_or_insert_with(Box::<Ipv4CidrNode>::default)
            };
        }
        node.terminal_indices.push(index);
    }

    pub(super) fn visit_matches<F>(&self, ip: Ipv4Addr, mut visitor: F)
    where
        F: FnMut(usize),
    {
        let mut node = &self.root;
        for index in &node.terminal_indices {
            visitor(*index);
        }

        let bits = u32::from(ip);
        for depth in 0..32 {
            let next = if bit_u32(bits, depth) {
                node.one.as_deref()
            } else {
                node.zero.as_deref()
            };
            let Some(next) = next else {
                return;
            };
            node = next;
            for index in &node.terminal_indices {
                visitor(*index);
            }
        }
    }
}

impl Ipv6CidrTrie {
    pub(super) fn insert(&mut self, cidr: Ipv6Net, index: usize) {
        let mut node = &mut self.root;
        let bits = u128::from_be_bytes(cidr.network().octets());
        for depth in 0..cidr.prefix_len() {
            let bit = bit_u128(bits, depth);
            node = if bit {
                node.one.get_or_insert_with(Box::<Ipv6CidrNode>::default)
            } else {
                node.zero.get_or_insert_with(Box::<Ipv6CidrNode>::default)
            };
        }
        node.terminal_indices.push(index);
    }

    pub(super) fn visit_matches<F>(&self, ip: Ipv6Addr, mut visitor: F)
    where
        F: FnMut(usize),
    {
        let mut node = &self.root;
        for index in &node.terminal_indices {
            visitor(*index);
        }

        let bits = u128::from_be_bytes(ip.octets());
        for depth in 0..128 {
            let next = if bit_u128(bits, depth) {
                node.one.as_deref()
            } else {
                node.zero.as_deref()
            };
            let Some(next) = next else {
                return;
            };
            node = next;
            for index in &node.terminal_indices {
                visitor(*index);
            }
        }
    }
}

fn bit_u32(value: u32, depth: u8) -> bool {
    let shift = 31 - depth;
    ((value >> shift) & 1) == 1
}

fn bit_u128(value: u128, depth: u8) -> bool {
    let shift = 127 - depth;
    ((value >> shift) & 1) == 1
}
