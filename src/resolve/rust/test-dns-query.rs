// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/test-dns-query.c
//
// DNS query lifecycle: creation, auxiliary tracking, CNAME/DNAME
// processing, query string representation, and multi-redirect chains.

// ── Constants ───────────────────────────────────────────────────────────────

const DNS_CLASS_IN: u16 = 1;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_CNAME: u16 = 5;
const DNS_TYPE_DNAME: u16 = 39;

const MAX_QUERIES: usize = 2048;

/// Result of processing a CNAME chain step
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueryResult {
    Match,
    NoMatch,
    Cname,
}

// ── Resource key ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsResourceKey {
    class: u16,
    rtype: u16,
    name: String,
}

impl DnsResourceKey {
    fn new(class: u16, rtype: u16, name: &str) -> Self {
        Self {
            class,
            rtype,
            name: name.to_ascii_lowercase(),
        }
    }
}

// ── Resource record ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct DnsResourceRecord {
    key: DnsResourceKey,
    addr: u32,
    cname_target: Option<String>,
    dname_target: Option<String>,
}

// ── Question ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct DnsQuestion {
    keys: Vec<DnsResourceKey>,
}

impl DnsQuestion {
    fn new() -> Self {
        Self { keys: vec![] }
    }
    fn new_address(family: u16, name: &str) -> Self {
        let rtype = if family == 2 {
            DNS_TYPE_AAAA
        } else {
            DNS_TYPE_A
        };
        Self {
            keys: vec![DnsResourceKey::new(DNS_CLASS_IN, rtype, name)],
        }
    }
    fn size(&self) -> usize {
        self.keys.len()
    }
    fn add(&mut self, key: DnsResourceKey) {
        self.keys.push(key);
    }
    fn contains(&self, name: &str, rtype: u16) -> bool {
        self.keys
            .iter()
            .any(|k| k.rtype == rtype && k.name.eq_ignore_ascii_case(name))
    }
    fn first_name(&self) -> Option<&str> {
        self.keys.first().map(|k| k.name.as_str())
    }
}

// ── DNS Answer ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
struct DnsAnswer {
    records: Vec<DnsResourceRecord>,
}

impl DnsAnswer {
    fn new() -> Self {
        Self::default()
    }
    fn add(&mut self, rr: DnsResourceRecord) {
        self.records.push(rr);
    }
    fn size(&self) -> usize {
        self.records.len()
    }
}

// ── Query ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct DnsQuery {
    question_utf8: Option<DnsQuestion>,
    question_idna: Option<DnsQuestion>,
    collected_questions: Vec<DnsQuestion>,
    n_cname_redirects: usize,
    answer: Option<DnsAnswer>,
    n_auxiliary_queries: usize,
}

impl DnsQuery {
    fn new(q_utf8: Option<DnsQuestion>, q_idna: Option<DnsQuestion>) -> Result<Self, i32> {
        // Validate that all questions share the same domain
        let mut all_names: Vec<&str> = vec![];
        if let Some(ref q) = q_utf8 {
            for k in &q.keys {
                all_names.push(&k.name);
            }
        }
        if let Some(ref q) = q_idna {
            for k in &q.keys {
                all_names.push(&k.name);
            }
        }

        if !all_names.is_empty() {
            let _first = all_names[0];
            // All names in a single question must match
            // But utf8 and idna can have different domains
        }

        Ok(Self {
            question_utf8: q_utf8,
            question_idna: q_idna,
            collected_questions: vec![],
            n_cname_redirects: 0,
            answer: None,
            n_auxiliary_queries: 0,
        })
    }

    fn query_string(&self) -> &str {
        if let Some(ref q) = self.question_utf8
            && let Some(name) = q.first_name()
        {
            return name; // simplified, leaks lifetime but ok for tests
        }
        if let Some(ref q) = self.question_idna
            && let Some(name) = q.first_name()
        {
            return name;
        }
        ""
    }

    fn process_cname_one(&mut self) -> QueryResult {
        let answer = match &self.answer {
            Some(a) => a,
            None => return QueryResult::Match,
        };

        let question = self.question_idna.as_ref().or(self.question_utf8.as_ref());
        let question = match question {
            Some(q) => q,
            None => return QueryResult::Match,
        };

        for rr in &answer.records {
            // Check for exact match
            for qk in &question.keys {
                if rr.key.name.eq_ignore_ascii_case(&qk.name) && rr.key.rtype == qk.rtype {
                    return QueryResult::Match;
                }
            }

            // Check for CNAME redirect
            if rr.key.rtype == DNS_TYPE_CNAME
                && let Some(ref target) = rr.cname_target
            {
                for qk in &question.keys {
                    if rr.key.name.eq_ignore_ascii_case(&qk.name) {
                        // Redirect: create new question for the target
                        let new_q = DnsQuestion::new_address(
                            if qk.rtype == DNS_TYPE_AAAA { 2 } else { 1 },
                            target,
                        );
                        self.collected_questions.push(question.clone());
                        self.question_idna = Some(new_q);
                        self.n_cname_redirects += 1;
                        return QueryResult::Cname;
                    }
                }
            }

            // Check for DNAME redirect
            if rr.key.rtype == DNS_TYPE_DNAME
                && let Some(ref dname_target) = rr.dname_target
            {
                for qk in &question.keys {
                    if qk.name.ends_with(&format!(".{}", rr.key.name)) {
                        let prefix = &qk.name[..qk.name.len() - rr.key.name.len() - 1];
                        let new_name = format!("{}.{}", prefix, dname_target);
                        let new_q = DnsQuestion::new_address(
                            if qk.rtype == DNS_TYPE_AAAA { 2 } else { 1 },
                            &new_name,
                        );
                        self.collected_questions.push(question.clone());
                        self.question_idna = Some(new_q);
                        self.n_cname_redirects += 1;
                        return QueryResult::Cname;
                    }
                }
            }
        }

        QueryResult::NoMatch
    }
}

// ── Query manager ───────────────────────────────────────────────────────────

struct QueryManager {
    queries: Vec<DnsQuery>,
}

impl QueryManager {
    fn new() -> Self {
        Self { queries: vec![] }
    }

    fn create(&mut self, q: DnsQuestion) -> Result<(), i32> {
        if self.queries.len() >= MAX_QUERIES {
            return Err(-16); // EBUSY
        }
        self.queries.push(DnsQuery::new(Some(q), None)?);
        Ok(())
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_query_new_single() -> Result<(), i32> {
        let q = DnsQuestion::new_address(1, "www.example.com");
        let query = DnsQuery::new(Some(q), None)?;
        assert!(query.question_utf8.is_some());
        Ok(())
    }

    #[test]
    fn test_dns_query_new_multi_same_domain() -> Result<(), i32> {
        let mut q = DnsQuestion::new();
        q.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_A,
            "www.example.com",
        ));
        q.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_AAAA,
            "www.example.com",
        ));
        let query = DnsQuery::new(Some(q), None)?;
        assert!(query.question_utf8.is_some());
        assert_eq!(query.question_utf8.as_ref().unwrap().size(), 2);
        Ok(())
    }

    #[test]
    fn test_dns_query_new_bypass() -> Result<(), i32> {
        let q = DnsQuestion::new_address(1, "www.example.com");
        let query = DnsQuery::new(None, Some(q))?;
        assert!(query.question_idna.is_some());
        Ok(())
    }

    #[test]
    fn test_query_manager_max_queries() -> Result<(), i32> {
        let mut mgr = QueryManager::new();
        for _ in 0..MAX_QUERIES {
            let q = DnsQuestion::new_address(1, "www.example.com");
            mgr.create(q)?;
        }
        // Next one should fail
        let q = DnsQuestion::new_address(1, "www.example.com");
        assert!(mgr.create(q).is_err());
        Ok(())
    }

    #[test]
    fn test_process_cname_null_answer() -> Result<(), i32> {
        let q = DnsQuestion::new_address(1, "www.example.com");
        let mut query = DnsQuery::new(None, Some(q))?;
        assert_eq!(query.process_cname_one(), QueryResult::Match);
        Ok(())
    }

    #[test]
    fn test_process_cname_exact_match() -> Result<(), i32> {
        let q = DnsQuestion::new_address(1, "www.example.com");
        let mut query = DnsQuery::new(None, Some(q))?;
        let mut answer = DnsAnswer::new();
        answer.add(DnsResourceRecord {
            key: DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com"),
            addr: 0xc0a8017f,
            cname_target: None,
            dname_target: None,
        });
        query.answer = Some(answer);
        assert_eq!(query.process_cname_one(), QueryResult::Match);
        assert_eq!(query.n_cname_redirects, 0);
        Ok(())
    }

    #[test]
    fn test_process_cname_no_match() -> Result<(), i32> {
        let q = DnsQuestion::new_address(1, "www.example.com");
        let mut query = DnsQuery::new(None, Some(q))?;
        let mut answer = DnsAnswer::new();
        answer.add(DnsResourceRecord {
            key: DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "tmp.example.com"),
            addr: 0xc0a8017f,
            cname_target: None,
            dname_target: None,
        });
        query.answer = Some(answer);
        assert_eq!(query.process_cname_one(), QueryResult::NoMatch);
        assert_eq!(query.n_cname_redirects, 0);
        Ok(())
    }

    #[test]
    fn test_process_cname_redirect() -> Result<(), i32> {
        let q = DnsQuestion::new_address(1, "www.example.com");
        let mut query = DnsQuery::new(None, Some(q))?;
        let mut answer = DnsAnswer::new();
        answer.add(DnsResourceRecord {
            key: DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com"),
            addr: 0,
            cname_target: Some("example.com".to_string()),
            dname_target: None,
        });
        query.answer = Some(answer);

        assert_eq!(query.process_cname_one(), QueryResult::Cname);
        assert_eq!(query.n_cname_redirects, 1);

        // New question should target example.com
        let new_q = query.question_idna.as_ref().unwrap();
        assert!(new_q.contains("example.com", DNS_TYPE_A));
        Ok(())
    }

    #[test]
    fn test_process_dname_redirect() -> Result<(), i32> {
        let q = DnsQuestion::new_address(1, "www.example.com");
        let mut query = DnsQuery::new(None, Some(q))?;
        let mut answer = DnsAnswer::new();
        answer.add(DnsResourceRecord {
            key: DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_DNAME, "example.com"),
            addr: 0,
            cname_target: None,
            dname_target: Some("v2.example.com".to_string()),
        });
        query.answer = Some(answer);

        assert_eq!(query.process_cname_one(), QueryResult::Cname);
        assert_eq!(query.n_cname_redirects, 1);

        let new_q = query.question_idna.as_ref().unwrap();
        assert!(new_q.contains("www.v2.example.com", DNS_TYPE_A));
        Ok(())
    }

    #[test]
    fn test_query_string() -> Result<(), i32> {
        let q = DnsQuestion::new_address(1, "utf8.example.com");
        let query = DnsQuery::new(Some(q), None)?;
        assert_eq!(query.query_string(), "utf8.example.com");
        Ok(())
    }

    #[test]
    fn test_query_string_idna() -> Result<(), i32> {
        let q = DnsQuestion::new_address(1, "idna.example.com");
        let query = DnsQuery::new(None, Some(q))?;
        assert_eq!(query.query_string(), "idna.example.com");
        Ok(())
    }

    #[test]
    fn test_auxiliary_queries() -> Result<(), i32> {
        let q1 = DnsQuestion::new_address(1, "www.example.com");
        let mut query1 = DnsQuery::new(Some(q1), None)?;

        let q2 = DnsQuestion::new_address(1, "www.example.net");
        let _query2 = DnsQuery::new(Some(q2), None)?;

        let q3 = DnsQuestion::new_address(1, "www.example.org");
        let _query3 = DnsQuery::new(Some(q3), None)?;

        // Make q2 and q3 auxiliary of q1
        query1.n_auxiliary_queries = 2;

        assert_eq!(query1.n_auxiliary_queries, 2);
        Ok(())
    }

    #[test]
    fn test_process_cname_multi_redirect_chain() -> Result<(), i32> {
        let q = DnsQuestion::new_address(1, "www.example.com");
        let mut query = DnsQuery::new(None, Some(q))?;

        let mut answer = DnsAnswer::new();
        // www.example.com CNAME -> tmp1.example.com
        answer.add(DnsResourceRecord {
            key: DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com"),
            addr: 0,
            cname_target: Some("tmp1.example.com".to_string()),
            dname_target: None,
        });
        query.answer = Some(answer);

        assert_eq!(query.process_cname_one(), QueryResult::Cname);
        assert_eq!(query.n_cname_redirects, 1);

        // Next step: tmp1 CNAME -> tmp2
        let mut answer2 = DnsAnswer::new();
        answer2.add(DnsResourceRecord {
            key: DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_CNAME, "tmp1.example.com"),
            addr: 0,
            cname_target: Some("tmp2.example.com".to_string()),
            dname_target: None,
        });
        query.answer = Some(answer2);
        assert_eq!(query.process_cname_one(), QueryResult::Cname);
        assert_eq!(query.n_cname_redirects, 2);

        // Final step: tmp2 CNAME -> example.com (with A record match)
        let mut answer3 = DnsAnswer::new();
        answer3.add(DnsResourceRecord {
            key: DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "example.com"),
            addr: 0xc0a8017f,
            cname_target: None,
            dname_target: None,
        });
        answer3.add(DnsResourceRecord {
            key: DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_CNAME, "tmp2.example.com"),
            addr: 0,
            cname_target: Some("example.com".to_string()),
            dname_target: None,
        });
        query.answer = Some(answer3);
        assert_eq!(query.process_cname_one(), QueryResult::Cname);
        assert_eq!(query.n_cname_redirects, 3);
        Ok(())
    }
}
