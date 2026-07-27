// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/sort-util.c

use std::cmp::Ordering;

fn ordering_to_c_value(ordering: Ordering) -> i32 {
    match ordering {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

pub fn cmp_int(a: i32, b: i32) -> i32 {
    ordering_to_c_value(a.cmp(&b))
}

pub fn cmp_uint16(a: u16, b: u16) -> i32 {
    ordering_to_c_value(a.cmp(&b))
}

pub fn qsort_safe<T, F>(data: &mut [T], mut compar: F)
where
    F: FnMut(&T, &T) -> Ordering,
{
    if data.len() <= 1 {
        return;
    }

    data.sort_unstable_by(|left, right| compar(left, right));
}

pub fn qsort_r_safe<T, U, F>(data: &mut [T], userdata: &mut U, mut compar: F)
where
    F: FnMut(&T, &T, &mut U) -> Ordering,
{
    if data.len() <= 1 {
        return;
    }

    for i in 1..data.len() {
        let mut j = i;
        while j > 0 {
            let should_swap = {
                let left = &data[j - 1];
                let right = &data[j];
                compar(left, right, userdata) == Ordering::Greater
            };

            if !should_swap {
                break;
            }

            data.swap(j - 1, j);
            j -= 1;
        }
    }
}

pub fn bsearch_safe<T, F>(key: &T, data: &[T], mut compar: F) -> Option<usize>
where
    F: FnMut(&T, &T) -> Ordering,
{
    if data.is_empty() {
        return None;
    }

    data.binary_search_by(|probe| compar(probe, key)).ok()
}

pub fn xbsearch_r<T, U, F>(key: &T, data: &[T], userdata: &U, mut compar: F) -> Option<usize>
where
    F: FnMut(&T, &T, &U) -> Ordering,
{
    let mut lower = 0;
    let mut upper = data.len();

    while lower < upper {
        let index = (lower + upper) / 2;
        match compar(key, &data[index], userdata) {
            Ordering::Less => upper = index,
            Ordering::Greater => lower = index + 1,
            Ordering::Equal => return Some(index),
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmp_int_matches_c_cmp_macro() {
        assert_eq!(cmp_int(1, 2), -1);
        assert_eq!(cmp_int(2, 2), 0);
        assert_eq!(cmp_int(3, 2), 1);
    }

    #[test]
    fn cmp_uint16_matches_c_cmp_macro() {
        assert_eq!(cmp_uint16(0, 1), -1);
        assert_eq!(cmp_uint16(7, 7), 0);
        assert_eq!(cmp_uint16(9, 7), 1);
    }

    #[test]
    fn qsort_safe_is_noop_for_trivial_inputs() {
        let mut empty: [i32; 0] = [];
        qsort_safe(&mut empty, |a, b| a.cmp(b));
        assert_eq!(empty, []);

        let mut one = [5];
        qsort_safe(&mut one, |a, b| a.cmp(b));
        assert_eq!(one, [5]);
    }

    #[test]
    fn qsort_safe_sorts_using_callback() {
        let mut values = [3, 1, 4, 1, 5, 9];
        qsort_safe(&mut values, |a, b| a.cmp(b));
        assert_eq!(values, [1, 1, 3, 4, 5, 9]);
    }

    #[test]
    fn qsort_safe_supports_reverse_order() {
        let mut values = [1, 2, 3, 4];
        qsort_safe(&mut values, |a, b| b.cmp(a));
        assert_eq!(values, [4, 3, 2, 1]);
    }

    #[test]
    fn qsort_r_safe_threads_userdata_through_comparator() {
        let mut values = [1, 4, 2, 3];
        let mut descending = true;
        qsort_r_safe(&mut values, &mut descending, |a, b, descending| {
            if *descending {
                b.cmp(a)
            } else {
                a.cmp(b)
            }
        });
        assert_eq!(values, [4, 3, 2, 1]);
    }

    #[test]
    fn bsearch_safe_finds_existing_elements() {
        let values = [1, 3, 5, 7, 9];
        assert_eq!(bsearch_safe(&1, &values, |a, b| a.cmp(b)), Some(0));
        assert_eq!(bsearch_safe(&5, &values, |a, b| a.cmp(b)), Some(2));
        assert_eq!(bsearch_safe(&9, &values, |a, b| a.cmp(b)), Some(4));
    }

    #[test]
    fn bsearch_safe_returns_none_for_missing_or_empty_inputs() {
        let values = [1, 3, 5, 7, 9];
        assert_eq!(bsearch_safe(&4, &values, |a, b| a.cmp(b)), None);
        assert_eq!(bsearch_safe(&4, &[], |a: &i32, b: &i32| a.cmp(b)), None);
    }

    #[test]
    fn xbsearch_r_matches_manual_binary_search_semantics() {
        let values = [10, 20, 30, 40, 50];
        let offset = 10;
        assert_eq!(
            xbsearch_r(&40, &values, &offset, |key, probe, offset| (key - offset)
                .cmp(&(probe - offset))),
            Some(3)
        );
        assert_eq!(
            xbsearch_r(&25, &values, &offset, |key, probe, offset| (key - offset)
                .cmp(&(probe - offset))),
            None
        );
    }
}
