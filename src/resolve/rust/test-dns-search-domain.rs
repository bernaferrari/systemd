// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/test-dns-search-domain.c
//
// DNS search domain management: create, link, unlink, mark, move,
// find, and limit enforcement for system and per-link search domains.

use std::cell::RefCell;
use std::rc::Rc;

const MANAGER_SEARCH_DOMAINS_MAX: usize = 256;
const LINK_SEARCH_DOMAINS_MAX: usize = 256;

// ── DnsSearchDomain ─────────────────────────────────────────────────────────

#[derive(Debug)]
struct DnsSearchDomain {
    name: String,
    marked: bool,
    linked: bool,
    kind: SearchDomainKind,
    link_id: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SearchDomainKind {
    System,
    Link,
}

struct Manager {
    search_domains: Vec<Rc<RefCell<DnsSearchDomain>>>,
}

struct Link {
    id: u32,
    search_domains: Vec<Rc<RefCell<DnsSearchDomain>>>,
}

impl Manager {
    fn new() -> Self {
        Self {
            search_domains: Vec::new(),
        }
    }

    fn n_search_domains(&self) -> usize {
        self.search_domains.len()
    }

    fn add_system(&mut self, name: &str) -> Result<Rc<RefCell<DnsSearchDomain>>, i32> {
        if self.search_domains.len() >= MANAGER_SEARCH_DOMAINS_MAX {
            return Err(-7);
        }
        let sd = Rc::new(RefCell::new(DnsSearchDomain {
            name: name.trim_end_matches('.').to_string(),
            marked: false,
            linked: true,
            kind: SearchDomainKind::System,
            link_id: None,
        }));
        self.search_domains.push(sd.clone());
        Ok(sd)
    }

    fn unlink(&mut self, sd: &Rc<RefCell<DnsSearchDomain>>) {
        sd.borrow_mut().linked = false;
        self.search_domains.retain(|s| !Rc::ptr_eq(s, sd));
    }

    fn mark_all(&self) {
        for sd in &self.search_domains {
            sd.borrow_mut().marked = true;
        }
    }

    fn move_back_and_unmark(&mut self, sd: &Rc<RefCell<DnsSearchDomain>>) {
        let is_marked = sd.borrow().marked;
        sd.borrow_mut().marked = false;
        if is_marked {
            let idx = self
                .search_domains
                .iter()
                .position(|s| Rc::ptr_eq(s, sd))
                .unwrap();
            let item = self.search_domains.remove(idx);
            self.search_domains.push(item);
        }
    }

    fn unlink_marked(&mut self) -> bool {
        let marked: Vec<_> = self
            .search_domains
            .iter()
            .filter(|s| s.borrow().marked)
            .cloned()
            .collect();
        let any = !marked.is_empty();
        for sd in &marked {
            self.unlink(sd);
        }
        any
    }

    fn find(&self, name: &str) -> Option<Rc<RefCell<DnsSearchDomain>>> {
        let normalized = name.trim_end_matches('.').to_ascii_lowercase();
        self.search_domains
            .iter()
            .find(|s| s.borrow().name.to_ascii_lowercase() == normalized)
            .cloned()
    }

    fn domain_names(&self) -> Vec<String> {
        self.search_domains
            .iter()
            .map(|s| s.borrow().name.clone())
            .collect()
    }
}

impl Link {
    fn new(id: u32) -> Self {
        Self {
            id,
            search_domains: Vec::new(),
        }
    }

    fn n_search_domains(&self) -> usize {
        self.search_domains.len()
    }

    fn add(
        &mut self,
        manager: &mut Manager,
        name: &str,
    ) -> Result<Rc<RefCell<DnsSearchDomain>>, i32> {
        if self.search_domains.len() >= LINK_SEARCH_DOMAINS_MAX {
            return Err(-7);
        }
        let sd = Rc::new(RefCell::new(DnsSearchDomain {
            name: name.trim_end_matches('.').to_string(),
            marked: false,
            linked: true,
            kind: SearchDomainKind::Link,
            link_id: Some(self.id),
        }));
        self.search_domains.push(sd.clone());
        manager.search_domains.push(sd.clone());
        Ok(sd)
    }

    fn unlink(&mut self, sd: &Rc<RefCell<DnsSearchDomain>>) {
        sd.borrow_mut().linked = false;
        self.search_domains.retain(|s| !Rc::ptr_eq(s, sd));
    }

    fn domain_names(&self) -> Vec<String> {
        self.search_domains
            .iter()
            .map(|s| s.borrow().name.clone())
            .collect()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_domain_new_system() {
        let mut mgr = Manager::new();
        let sd = mgr.add_system("local").unwrap();
        assert!(sd.borrow().linked);
        assert_eq!(sd.borrow().name, "local");
        assert_eq!(mgr.n_search_domains(), 1);
    }

    #[test]
    fn test_search_domain_new_system_limit() {
        let mut mgr = Manager::new();
        for i in 0..MANAGER_SEARCH_DOMAINS_MAX {
            let sd = mgr.add_system("local").unwrap();
            assert_eq!(mgr.n_search_domains(), i + 1);
        }
        let result = mgr.add_system("local");
        assert!(result.is_err());
    }

    #[test]
    fn test_search_domain_new_link() {
        let mut mgr = Manager::new();
        let mut link = Link::new(1);
        let sd = link.add(&mut mgr, "local.").unwrap();
        assert!(sd.borrow().linked);
        assert_eq!(sd.borrow().name, "local");
        assert_eq!(link.n_search_domains(), 1);
    }

    #[test]
    fn test_search_domain_new_link_limit() {
        let mut mgr = Manager::new();
        let mut link = Link::new(1);
        for i in 0..LINK_SEARCH_DOMAINS_MAX {
            link.add(&mut mgr, "local").unwrap();
            assert_eq!(link.n_search_domains(), i + 1);
        }
        let result = link.add(&mut mgr, "local");
        assert!(result.is_err());
    }

    #[test]
    fn test_search_domain_unlink_system() {
        let mut mgr = Manager::new();
        let sd1 = mgr.add_system("local").unwrap();
        let sd2 = mgr.add_system("vpn.example.com").unwrap();
        let sd3 = mgr.add_system("org").unwrap();

        assert!(sd2.borrow().linked);
        assert_eq!(mgr.n_search_domains(), 3);

        mgr.unlink(&sd2);
        assert_eq!(mgr.n_search_domains(), 2);
        assert_eq!(mgr.domain_names(), vec!["local", "org"]);
    }

    #[test]
    fn test_search_domain_unlink_link() {
        let mut mgr = Manager::new();
        let mut link = Link::new(1);
        let sd1 = link.add(&mut mgr, "local").unwrap();
        let sd2 = link.add(&mut mgr, "vpn.example.com").unwrap();
        let sd3 = link.add(&mut mgr, "org").unwrap();

        assert!(sd2.borrow().linked);
        assert_eq!(link.n_search_domains(), 3);

        link.unlink(&sd2);
        assert_eq!(link.n_search_domains(), 2);
        assert_eq!(link.domain_names(), vec!["local", "org"]);
    }

    #[test]
    fn test_search_domain_mark_all() {
        let mut mgr = Manager::new();
        let sd1 = mgr.add_system("local").unwrap();
        let sd2 = mgr.add_system("vpn.example.com").unwrap();
        let sd3 = mgr.add_system("org").unwrap();

        assert!(!sd1.borrow().marked);
        assert!(!sd2.borrow().marked);
        assert!(!sd3.borrow().marked);

        mgr.mark_all();

        assert!(sd1.borrow().marked);
        assert!(sd2.borrow().marked);
        assert!(sd3.borrow().marked);
    }

    #[test]
    fn test_search_domain_move_back_and_unmark() {
        let mut mgr = Manager::new();
        let sd1 = mgr.add_system("local").unwrap();
        let _sd2 = mgr.add_system("vpn.example.com").unwrap();
        let _sd3 = mgr.add_system("org").unwrap();

        mgr.move_back_and_unmark(&sd1);
        assert_eq!(mgr.domain_names(), vec!["local", "vpn.example.com", "org"]);

        sd1.borrow_mut().marked = true;
        mgr.move_back_and_unmark(&sd1);
        assert_eq!(mgr.domain_names(), vec!["vpn.example.com", "org", "local"]);
    }

    #[test]
    fn test_search_domain_unlink_marked() {
        let mut mgr = Manager::new();
        let sd1 = mgr.add_system("local").unwrap();
        let sd2 = mgr.add_system("vpn.example.com").unwrap();
        let _sd3 = mgr.add_system("org").unwrap();

        assert!(!mgr.unlink_marked());
        assert_eq!(mgr.n_search_domains(), 3);
        assert_eq!(mgr.domain_names(), vec!["local", "vpn.example.com", "org"]);

        sd2.borrow_mut().marked = true;
        assert!(mgr.unlink_marked());
        assert_eq!(mgr.n_search_domains(), 2);
        assert_eq!(mgr.domain_names(), vec!["local", "org"]);

        sd1.borrow_mut().marked = true;
        assert!(mgr.unlink_marked());
        assert_eq!(mgr.n_search_domains(), 1);
        assert_eq!(mgr.domain_names(), vec!["org"]);
    }

    #[test]
    fn test_search_domain_find() {
        let mut mgr = Manager::new();
        let sd1 = mgr.add_system("local").unwrap();
        let sd2 = mgr.add_system("vpn.example.com").unwrap();
        let sd3 = mgr.add_system("org").unwrap();

        let found = mgr.find("local").unwrap();
        assert!(Rc::ptr_eq(&found, &sd1));

        let found = mgr.find("org").unwrap();
        assert!(Rc::ptr_eq(&found, &sd3));

        let found = mgr.find("vpn.example.com").unwrap();
        assert!(Rc::ptr_eq(&found, &sd2));

        assert!(mgr.find("co.uk").is_none());
    }
}
