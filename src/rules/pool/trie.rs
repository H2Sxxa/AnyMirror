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
    root: CidrNode,
}

#[derive(Debug, Clone, Default)]
struct CidrNode {
    zero: Option<Box<CidrNode>>,
    one: Option<Box<CidrNode>>,
    terminal_indices: Vec<usize>,
    min_rule_index: Option<usize>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct Ipv6CidrTrie {
    root: CidrNode,
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
        insert_cidr(
            &mut self.root,
            u128::from(u32::from(cidr.network())),
            cidr.prefix_len(),
            32,
            index,
        );
    }

    pub(super) fn visit_matches<F>(&self, ip: Ipv4Addr, cutoff_index: Option<usize>, mut visitor: F)
    where
        F: FnMut(usize),
    {
        visit_cidr_matches(
            &self.root,
            u128::from(u32::from(ip)),
            32,
            cutoff_index,
            &mut visitor,
        );
    }
}

impl Ipv6CidrTrie {
    pub(super) fn insert(&mut self, cidr: Ipv6Net, index: usize) {
        insert_cidr(
            &mut self.root,
            u128::from_be_bytes(cidr.network().octets()),
            cidr.prefix_len(),
            128,
            index,
        );
    }

    pub(super) fn visit_matches<F>(&self, ip: Ipv6Addr, cutoff_index: Option<usize>, mut visitor: F)
    where
        F: FnMut(usize),
    {
        visit_cidr_matches(
            &self.root,
            u128::from_be_bytes(ip.octets()),
            128,
            cutoff_index,
            &mut visitor,
        );
    }
}

impl CidrNode {
    fn child(&self, bit: bool) -> Option<&Self> {
        if bit {
            self.one.as_deref()
        } else {
            self.zero.as_deref()
        }
    }

    fn child_mut(&mut self, bit: bool) -> &mut Self {
        if bit {
            self.one.get_or_insert_with(Box::<Self>::default)
        } else {
            self.zero.get_or_insert_with(Box::<Self>::default)
        }
    }
}

fn insert_cidr(root: &mut CidrNode, bits: u128, prefix_len: u8, max_depth: u8, index: usize) {
    let mut node = root;
    update_min_rule_index(&mut node.min_rule_index, index);
    for depth in 0..prefix_len {
        node = node.child_mut(cidr_bit(bits, max_depth, depth));
        update_min_rule_index(&mut node.min_rule_index, index);
    }
    node.terminal_indices.push(index);
}

fn visit_cidr_matches<F>(
    root: &CidrNode,
    bits: u128,
    max_depth: u8,
    cutoff_index: Option<usize>,
    visitor: &mut F,
) where
    F: FnMut(usize),
{
    if should_skip_subtree(root.min_rule_index, cutoff_index) {
        return;
    }

    let mut node = root;
    visit_terminal_indices(&node.terminal_indices, cutoff_index, visitor);

    for depth in 0..max_depth {
        let Some(next) = node.child(cidr_bit(bits, max_depth, depth)) else {
            return;
        };
        if should_skip_subtree(next.min_rule_index, cutoff_index) {
            return;
        }
        node = next;
        visit_terminal_indices(&node.terminal_indices, cutoff_index, visitor);
    }
}

fn visit_terminal_indices<F>(indices: &[usize], cutoff_index: Option<usize>, visitor: &mut F)
where
    F: FnMut(usize),
{
    for index in indices {
        if should_skip_index(*index, cutoff_index) {
            continue;
        }
        visitor(*index);
    }
}

fn cidr_bit(value: u128, max_depth: u8, depth: u8) -> bool {
    let shift = u32::from(max_depth - depth - 1);
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
