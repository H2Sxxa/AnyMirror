use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};

#[derive(Debug, Clone, Default)]
pub(super) struct PrefixPathTrie {
    root: PrefixPathNode,
}

#[derive(Debug, Clone, Default)]
struct PrefixPathNode {
    children: HashMap<u8, PrefixPathNode>,
    terminals: Vec<PrefixTerminal>,
    min_rule_index: Option<usize>,
}

#[derive(Debug, Clone)]
struct PrefixTerminal {
    index: usize,
    matches_descendants: bool,
}

#[derive(Debug, Clone, Default)]
pub(super) struct SuffixHostTrie {
    root: SuffixHostNode,
}

#[derive(Debug, Clone, Default)]
struct SuffixHostNode {
    children: HashMap<Box<str>, SuffixHostNode>,
    rule_indices: Vec<usize>,
    dns_terminal: bool,
    min_rule_index: Option<usize>,
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
    min_rule_index: Option<usize>,
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
    min_rule_index: Option<usize>,
}

impl PrefixPathTrie {
    pub(super) fn insert(&mut self, path: &str, index: usize) {
        let mut node = &mut self.root;
        update_min_rule_index(&mut node.min_rule_index, index);
        for byte in path.bytes() {
            node = node.children.entry(byte).or_default();
            update_min_rule_index(&mut node.min_rule_index, index);
        }
        node.terminals.push(PrefixTerminal {
            index,
            matches_descendants: path == "/" || path.ends_with('/'),
        });
    }

    pub(super) fn visit_matches<F>(&self, path: &str, cutoff_index: Option<usize>, mut visitor: F)
    where
        F: FnMut(usize),
    {
        if should_skip_subtree(self.root.min_rule_index, cutoff_index) {
            return;
        }

        let mut node = &self.root;
        for (offset, byte) in path.bytes().enumerate() {
            let Some(next) = node.children.get(&byte) else {
                return;
            };
            if should_skip_subtree(next.min_rule_index, cutoff_index) {
                return;
            }
            node = next;
            let next_byte = path.as_bytes().get(offset + 1).copied();
            for terminal in &node.terminals {
                if should_skip_index(terminal.index, cutoff_index) {
                    continue;
                }
                if terminal.matches_descendants || matches!(next_byte, None | Some(b'/')) {
                    visitor(terminal.index);
                }
            }
        }
    }
}

impl SuffixHostTrie {
    pub(super) fn insert_rule(&mut self, suffix: &str, index: usize) {
        let mut node = &mut self.root;
        update_min_rule_index(&mut node.min_rule_index, index);
        for label in suffix.rsplit('.') {
            node = node.children.entry(label.into()).or_default();
            update_min_rule_index(&mut node.min_rule_index, index);
        }
        node.rule_indices.push(index);
    }

    pub(super) fn mark_dns(&mut self, suffix: &str) {
        let mut node = &mut self.root;
        for label in suffix.rsplit('.') {
            node = node.children.entry(label.into()).or_default();
        }
        node.dns_terminal = true;
    }

    pub(super) fn visit_rule_matches<F>(
        &self,
        host: &str,
        cutoff_index: Option<usize>,
        mut visitor: F,
    ) where
        F: FnMut(usize),
    {
        if should_skip_subtree(self.root.min_rule_index, cutoff_index) {
            return;
        }

        let mut node = &self.root;
        for label in host.rsplit('.') {
            let Some(next) = node.children.get(label) else {
                return;
            };
            if should_skip_subtree(next.min_rule_index, cutoff_index) {
                return;
            }
            node = next;
            for index in &node.rule_indices {
                if should_skip_index(*index, cutoff_index) {
                    continue;
                }
                visitor(*index);
            }
        }
    }

    pub(super) fn matches(&self, host: &str) -> bool {
        let mut node = &self.root;
        for label in host.rsplit('.') {
            let Some(next) = node.children.get(label) else {
                return false;
            };
            node = next;
            if node.dns_terminal {
                return true;
            }
        }
        false
    }
}

impl Ipv4CidrTrie {
    pub(super) fn insert(&mut self, cidr: Ipv4Net, index: usize) {
        let mut node = &mut self.root;
        update_min_rule_index(&mut node.min_rule_index, index);
        let bits = u32::from(cidr.network());
        for depth in 0..cidr.prefix_len() {
            let bit = bit_u32(bits, depth);
            node = if bit {
                node.one.get_or_insert_with(Box::<Ipv4CidrNode>::default)
            } else {
                node.zero.get_or_insert_with(Box::<Ipv4CidrNode>::default)
            };
            update_min_rule_index(&mut node.min_rule_index, index);
        }
        node.terminal_indices.push(index);
    }

    pub(super) fn visit_matches<F>(&self, ip: Ipv4Addr, cutoff_index: Option<usize>, mut visitor: F)
    where
        F: FnMut(usize),
    {
        if should_skip_subtree(self.root.min_rule_index, cutoff_index) {
            return;
        }

        let mut node = &self.root;
        for index in &node.terminal_indices {
            if should_skip_index(*index, cutoff_index) {
                continue;
            }
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
            if should_skip_subtree(next.min_rule_index, cutoff_index) {
                return;
            }
            node = next;
            for index in &node.terminal_indices {
                if should_skip_index(*index, cutoff_index) {
                    continue;
                }
                visitor(*index);
            }
        }
    }
}

impl Ipv6CidrTrie {
    pub(super) fn insert(&mut self, cidr: Ipv6Net, index: usize) {
        let mut node = &mut self.root;
        update_min_rule_index(&mut node.min_rule_index, index);
        let bits = u128::from_be_bytes(cidr.network().octets());
        for depth in 0..cidr.prefix_len() {
            let bit = bit_u128(bits, depth);
            node = if bit {
                node.one.get_or_insert_with(Box::<Ipv6CidrNode>::default)
            } else {
                node.zero.get_or_insert_with(Box::<Ipv6CidrNode>::default)
            };
            update_min_rule_index(&mut node.min_rule_index, index);
        }
        node.terminal_indices.push(index);
    }

    pub(super) fn visit_matches<F>(&self, ip: Ipv6Addr, cutoff_index: Option<usize>, mut visitor: F)
    where
        F: FnMut(usize),
    {
        if should_skip_subtree(self.root.min_rule_index, cutoff_index) {
            return;
        }

        let mut node = &self.root;
        for index in &node.terminal_indices {
            if should_skip_index(*index, cutoff_index) {
                continue;
            }
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
            if should_skip_subtree(next.min_rule_index, cutoff_index) {
                return;
            }
            node = next;
            for index in &node.terminal_indices {
                if should_skip_index(*index, cutoff_index) {
                    continue;
                }
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

fn update_min_rule_index(slot: &mut Option<usize>, index: usize) {
    match slot {
        Some(current) if *current <= index => {}
        Some(current) => *current = index,
        None => *slot = Some(index),
    }
}

fn should_skip_index(index: usize, cutoff_index: Option<usize>) -> bool {
    cutoff_index.is_some_and(|cutoff| index >= cutoff)
}

fn should_skip_subtree(min_rule_index: Option<usize>, cutoff_index: Option<usize>) -> bool {
    min_rule_index.is_none()
        || cutoff_index
            .zip(min_rule_index)
            .is_some_and(|(cutoff, min_index)| min_index >= cutoff)
}
