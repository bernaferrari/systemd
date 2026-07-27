/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C xml.c tokenizer vs Rust */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"

/* C headers */
#include "xml.h"

/* Rust FFI */
#include "rust/xml_tokenizer.h"

/* Helper: run both tokenizers on the same input and compare */
static int next_c(const char **p, char **name, void **state, unsigned *line) {
        return xml_tokenize(p, name, state, line);
}

static int next_r(const char **p, char **name, void **state, unsigned *line) {
        return rs_xml_tokenize(p, name, state, line);
}

static void test_simple_tag(void) {
        const char *input = "<root>";
        const char *cp = input, *rp = input;
        char *cn = NULL, *rn = NULL;
        void *cs = NULL, *rs = NULL;
        unsigned cl = 0, rl = 0;
        int cv, rv;

        cv = next_c(&cp, &cn, &cs, &cl);
        rv = next_r(&rp, &rn, &rs, &rl);
        assert_se(cv == rv);
        assert_se(cv == XML_TAG_OPEN);
        assert_se(streq(cn, rn));
        assert_se(streq(cn, "root"));
        free(cn); free(rn);
}

static void test_text_and_close_tag(void) {
        const char *input = "<root>hello</root>";
        const char *cp = input, *rp = input;
        char *cn = NULL, *rn = NULL;
        void *cs = NULL, *rs = NULL;
        unsigned cl = 0, rl = 0;
        int cv, rv;

        /* Open tag */
        cv = next_c(&cp, &cn, &cs, &cl);
        rv = next_r(&rp, &rn, &rs, &rl);
        assert_se(cv == rv);
        assert_se(cv == XML_TAG_OPEN);
        assert_se(streq(cn, rn));
        free(cn); free(rn);

        /* Text */
        cv = next_c(&cp, &cn, &cs, &cl);
        rv = next_r(&rp, &rn, &rs, &rl);
        assert_se(cv == rv);
        assert_se(cv == XML_TEXT);
        assert_se(streq(cn, rn));
        assert_se(streq(cn, "hello"));
        free(cn); free(rn);

        /* Close tag */
        cv = next_c(&cp, &cn, &cs, &cl);
        rv = next_r(&rp, &rn, &rs, &rl);
        assert_se(cv == rv);
        assert_se(cv == XML_TAG_CLOSE);
        assert_se(streq(cn, rn));
        assert_se(streq(cn, "root"));
        free(cn); free(rn);

        /* End */
        cv = next_c(&cp, &cn, &cs, &cl);
        rv = next_r(&rp, &rn, &rs, &rl);
        assert_se(cv == rv);
        assert_se(cv == XML_END);
}

static void test_empty_tag(void) {
        const char *input = "<br/>";
        const char *cp = input, *rp = input;
        char *cn = NULL, *rn = NULL;
        void *cs = NULL, *rs = NULL;
        int cv, rv;

        /* Open tag: <br */
        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == XML_TAG_OPEN);
        assert_se(streq(cn, rn));
        assert_se(streq(cn, "br"));
        free(cn); free(rn);

        /* Empty close: /> */
        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == XML_TAG_CLOSE_EMPTY);
        assert_se(cn == NULL);
        assert_se(rn == NULL);
}

static void test_attributes(void) {
        const char *input = "<tag attr='value'>text</tag>";
        const char *cp = input, *rp = input;
        char *cn = NULL, *rn = NULL;
        void *cs = NULL, *rs = NULL;
        int cv, rv;

        /* Open tag */
        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == XML_TAG_OPEN);
        assert_se(streq(cn, rn));
        free(cn); free(rn);

        /* Attribute name */
        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == XML_ATTRIBUTE_NAME);
        assert_se(streq(cn, rn));
        assert_se(streq(cn, "attr"));
        free(cn); free(rn);

        /* Attribute value */
        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == XML_ATTRIBUTE_VALUE);
        assert_se(streq(cn, rn));
        assert_se(streq(cn, "value"));
        free(cn); free(rn);

        /* Text */
        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == XML_TEXT);
        assert_se(streq(cn, rn));
        free(cn); free(rn);

        /* Close tag */
        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == XML_TAG_CLOSE);
        free(cn); free(rn);
}

static void test_comment(void) {
        const char *input = "before<!-- comment -->after";
        const char *cp = input, *rp = input;
        char *cn = NULL, *rn = NULL;
        void *cs = NULL, *rs = NULL;
        int cv, rv;

        /* Text before */
        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == XML_TEXT);
        assert_se(streq(cn, rn));
        assert_se(streq(cn, "before"));
        free(cn); free(rn);

        /* Text after (comment is skipped) */
        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == XML_TEXT);
        assert_se(streq(cn, rn));
        assert_se(streq(cn, "after"));
        free(cn); free(rn);

        /* End */
        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == XML_END);
}

static void test_processing_instruction(void) {
        const char *input = "<?xml version='1.0'?><root/>";
        const char *cp = input, *rp = input;
        char *cn = NULL, *rn = NULL;
        void *cs = NULL, *rs = NULL;
        int cv, rv;

        /* Processing instruction is skipped, next is open tag */
        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == XML_TAG_OPEN);
        assert_se(streq(cn, rn));
        assert_se(streq(cn, "root"));
        free(cn); free(rn);

        /* Then empty close */
        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == XML_TAG_CLOSE_EMPTY);
}

static void test_dtd(void) {
        const char *input = "<!DOCTYPE html><root/>";
        const char *cp = input, *rp = input;
        char *cn = NULL, *rn = NULL;
        void *cs = NULL, *rs = NULL;
        int cv, rv;

        /* DTD is skipped, next is open tag */
        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == XML_TAG_OPEN);
        assert_se(streq(cn, rn));
        assert_se(streq(cn, "root"));
        free(cn); free(rn);

        /* Then empty close */
        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == XML_TAG_CLOSE_EMPTY);
}

static void test_unquoted_attribute(void) {
        const char *input = "<tag attr=value>";
        const char *cp = input, *rp = input;
        char *cn = NULL, *rn = NULL;
        void *cs = NULL, *rs = NULL;
        int cv, rv;

        /* Open tag */
        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == XML_TAG_OPEN);
        free(cn); free(rn);

        /* Attribute name */
        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == XML_ATTRIBUTE_NAME);
        free(cn); free(rn);

        /* Attribute value (unquoted) */
        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == XML_ATTRIBUTE_VALUE);
        assert_se(streq(cn, rn));
        assert_se(streq(cn, "value"));
        free(cn); free(rn);
}

static void test_double_quoted_attribute(void) {
        const char *input = R"(<tag attr="value"/>)";
        const char *cp = input, *rp = input;
        char *cn = NULL, *rn = NULL;
        void *cs = NULL, *rs = NULL;
        int cv, rv;

        /* Open tag */
        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        free(cn); free(rn);

        /* Attribute name */
        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        free(cn); free(rn);

        /* Attribute value */
        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(streq(cn, rn));
        assert_se(streq(cn, "value"));
        free(cn); free(rn);

        /* Empty tag */
        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == XML_TAG_CLOSE_EMPTY);
}

static void test_line_counting(void) {
        const char *input = "line1\n<root>\n</root>";
        const char *cp = input, *rp = input;
        char *cn = NULL, *rn = NULL;
        void *cs = NULL, *rs = NULL;
        unsigned cl = 0, rl = 0;
        int cv, rv;

        /* Text: "line1\n" */
        cv = next_c(&cp, &cn, &cs, &cl);
        rv = next_r(&rp, &rn, &rs, &rl);
        assert_se(cv == rv);
        assert_se(cv == XML_TEXT);
        assert_se(streq(cn, rn));
        assert_se(cl == rl);
        assert_se(cl == 2); /* 1 newline */
        free(cn); free(rn);

        /* Open tag */
        cv = next_c(&cp, &cn, &cs, &cl);
        rv = next_r(&rp, &rn, &rs, &rl);
        assert_se(cv == rv);
        assert_se(cv == XML_TAG_OPEN);
        assert_se(cl == rl);
        assert_se(cl == 2);
        free(cn); free(rn);

        /* Text: "\n" */
        cv = next_c(&cp, &cn, &cs, &cl);
        rv = next_r(&rp, &rn, &rs, &rl);
        assert_se(cv == rv);
        assert_se(cv == XML_TEXT);
        assert_se(cl == rl);
        assert_se(cl == 3);
        free(cn); free(rn);

        /* Close tag */
        cv = next_c(&cp, &cn, &cs, &cl);
        rv = next_r(&rp, &rn, &rs, &rl);
        assert_se(cv == rv);
        assert_se(cv == XML_TAG_CLOSE);
        assert_se(cl == rl);
        assert_se(cl == 3);
        free(cn); free(rn);
}

static void test_invalid_comment(void) {
        const char *input = "<!-- unclosed";
        const char *cp = input, *rp = input;
        char *cn = NULL, *rn = NULL;
        void *cs = NULL, *rs = NULL;
        int cv, rv;

        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == -EINVAL);
}

static void test_invalid_processing_instruction(void) {
        const char *input = "<? unclosed";
        const char *cp = input, *rp = input;
        char *cn = NULL, *rn = NULL;
        void *cs = NULL, *rs = NULL;
        int cv, rv;

        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == -EINVAL);
}

static void test_empty_input(void) {
        const char *input = "";
        const char *cp = input, *rp = input;
        char *cn = NULL, *rn = NULL;
        void *cs = NULL, *rs = NULL;
        int cv, rv;

        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == XML_END);
}

static void test_nested_tags(void) {
        const char *input = "<a><b></b></a>";
        const char *cp = input, *rp = input;
        char *cn = NULL, *rn = NULL;
        void *cs = NULL, *rs = NULL;
        int cv, rv, i;

        const char *expected_tags[] = {"a", "b", "b", "a"};
        const int expected_types[] = {XML_TAG_OPEN, XML_TAG_OPEN, XML_TAG_CLOSE, XML_TAG_CLOSE};

        for (i = 0; i < 4; i++) {
                cv = next_c(&cp, &cn, &cs, NULL);
                rv = next_r(&rp, &rn, &rs, NULL);
                assert_se(cv == rv);
                assert_se(cv == expected_types[i]);
                assert_se(streq(cn, rn));
                assert_se(streq(cn, expected_tags[i]));
                free(cn); free(rn);
        }

        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == XML_END);
}

static void test_multiple_attributes(void) {
        const char *input = "<tag a='1' b='2'>";
        const char *cp = input, *rp = input;
        char *cn = NULL, *rn = NULL;
        void *cs = NULL, *rs = NULL;
        int cv, rv;

        /* Open tag */
        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        free(cn); free(rn);

        /* attr a */
        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == XML_ATTRIBUTE_NAME);
        free(cn); free(rn);

        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == XML_ATTRIBUTE_VALUE);
        assert_se(streq(cn, rn));
        assert_se(streq(cn, "1"));
        free(cn); free(rn);

        /* attr b */
        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == XML_ATTRIBUTE_NAME);
        free(cn); free(rn);

        cv = next_c(&cp, &cn, &cs, NULL);
        rv = next_r(&rp, &rn, &rs, NULL);
        assert_se(cv == rv);
        assert_se(cv == XML_ATTRIBUTE_VALUE);
        assert_se(streq(cn, rn));
        assert_se(streq(cn, "2"));
        free(cn); free(rn);
}

int main(int argc, char **argv) {
        test_simple_tag();
        test_text_and_close_tag();
        test_empty_tag();
        test_attributes();
        test_comment();
        test_processing_instruction();
        test_dtd();
        test_unquoted_attribute();
        test_double_quoted_attribute();
        test_line_counting();
        test_invalid_comment();
        test_invalid_processing_instruction();
        test_empty_input();
        test_nested_tags();
        test_multiple_attributes();
        return 0;
}
