/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "extract-word.h"
#include "tests.h"

TEST(extract_first_word_basic) {
        _cleanup_free_ char *word = NULL;
        const char *p;

        p = "hello world";
        ASSERT_OK(extract_first_word(&p, &word, NULL, 0));
        ASSERT_STREQ(word, "hello");

        word = mfree(word);
        ASSERT_OK(extract_first_word(&p, &word, NULL, 0));
        ASSERT_STREQ(word, "world");

        word = mfree(word);
        ASSERT_EQ(extract_first_word(&p, &word, NULL, 0), 0);

        /* Empty string */
        p = "";
        ASSERT_EQ(extract_first_word(&p, &word, NULL, 0), 0);
        ASSERT_NULL(word);
}

TEST(extract_first_word_with_separators) {
        _cleanup_free_ char *word = NULL;
        const char *p = "one,two,three";

        ASSERT_OK(extract_first_word(&p, &word, ",", 0));
        ASSERT_STREQ(word, "one");
        word = mfree(word);
        ASSERT_OK(extract_first_word(&p, &word, ",", 0));
        ASSERT_STREQ(word, "two");
        word = mfree(word);
        ASSERT_OK(extract_first_word(&p, &word, ",", 0));
        ASSERT_STREQ(word, "three");
}

TEST(extract_first_word_quoted) {
        _cleanup_free_ char *word = NULL;
        const char *p;

        /* Double-quoted word - needs EXTRACT_KEEP_QUOTE to handle quotes */
        p = "\"hello world\"";
        ASSERT_OK(extract_first_word(&p, &word, NULL, EXTRACT_KEEP_QUOTE));
        ASSERT_STREQ(word, "\"hello world\"");
        word = mfree(word);

        /* EXTRACT_UNQUOTE removes the quotes */
        p = "\"hello world\"";
        ASSERT_OK(extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE));
        ASSERT_STREQ(word, "hello world");
        word = mfree(word);

        /* Single-quoted with EXTRACT_UNQUOTE */
        p = "'hello world'";
        ASSERT_OK(extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE));
        ASSERT_STREQ(word, "hello world");
}

TEST(extract_first_word_unquote) {
        _cleanup_free_ char *word = NULL;
        const char *p;

        /* EXTRACT_UNQUOTE removes quotes */
        p = "'hello'";
        ASSERT_OK(extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE));
        ASSERT_STREQ(word, "hello");
        word = mfree(word);

        /* EXTRACT_KEEP_QUOTE retains quotes */
        p = "'hello'";
        ASSERT_OK(extract_first_word(&p, &word, NULL, EXTRACT_KEEP_QUOTE));
        ASSERT_STREQ(word, "'hello'");
}

TEST(extract_first_word_cunescape) {
        _cleanup_free_ char *word = NULL;
        const char *p;

        /* EXTRACT_CUNESCAPE unescape sequences */
        p = "hello\\nworld";
        ASSERT_OK(extract_first_word(&p, &word, NULL, EXTRACT_CUNESCAPE));
        ASSERT_STREQ(word, "hello\nworld");
        word = mfree(word);

        /* Tab escape */
        p = "tab\\there";
        ASSERT_OK(extract_first_word(&p, &word, NULL, EXTRACT_CUNESCAPE));
        ASSERT_STREQ(word, "tab\there");
}

TEST(extract_first_word_dont_coalesce) {
        _cleanup_free_ char *word = NULL;
        const char *p;

        /* EXTRACT_DONT_COALESCE_SEPARATORS treats multiple separators as separate */
        p = "one,,two";
        ASSERT_OK(extract_first_word(&p, &word, ",", EXTRACT_DONT_COALESCE_SEPARATORS));
        ASSERT_STREQ(word, "one");
        word = mfree(word);
        /* Empty word between separators */
        ASSERT_OK(extract_first_word(&p, &word, ",", EXTRACT_DONT_COALESCE_SEPARATORS));
        ASSERT_STREQ(word, "");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
