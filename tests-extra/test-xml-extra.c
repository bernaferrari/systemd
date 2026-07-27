/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "tests.h"
#include "xml.h"

TEST(xml_tokenize_empty) {
        const char *input = "";
        void *state = NULL;
        _cleanup_free_ char *name = NULL;

        /* Empty input should return XML_END */
        assert_se(xml_tokenize(&input, &name, &state, NULL) == XML_END);
}

TEST(xml_tokenize_text) {
        const char *input = "hello world";
        void *state = NULL;
        _cleanup_free_ char *name = NULL;
        int t;

        t = xml_tokenize(&input, &name, &state, NULL);
        assert_se(t == XML_TEXT);
        assert_se(streq(name, "hello world"));
}

TEST(xml_tokenize_tag) {
        void *state = NULL;
        _cleanup_free_ char *name = NULL;
        int t;
        const char *input = "<test>content</test>";

        /* <test> */
        t = xml_tokenize(&input, &name, &state, NULL);
        assert_se(t == XML_TAG_OPEN);
        assert_se(streq(name, "test"));

        name = mfree(name);
        /* "content" */
        t = xml_tokenize(&input, &name, &state, NULL);
        assert_se(t == XML_TEXT);
        assert_se(streq(name, "content"));

        name = mfree(name);
        /* </test> */
        t = xml_tokenize(&input, &name, &state, NULL);
        assert_se(t == XML_TAG_CLOSE);
        assert_se(streq(name, "test"));

        name = mfree(name);
        /* End */
        t = xml_tokenize(&input, &name, &state, NULL);
        assert_se(t == XML_END);
}

TEST(xml_tokenize_self_closing) {
        void *state = NULL;
        _cleanup_free_ char *name = NULL;
        int t;
        const char *input = "<br/>";

        t = xml_tokenize(&input, &name, &state, NULL);
        assert_se(t == XML_TAG_OPEN || t == XML_TAG_CLOSE_EMPTY);
}

TEST(xml_tokenize_attribute) {
        void *state = NULL;
        _cleanup_free_ char *name = NULL;
        int t;
        const char *input = "<div class=\"test\">text</div>";

        /* <div */
        t = xml_tokenize(&input, &name, &state, NULL);
        assert_se(t == XML_TAG_OPEN);
        assert_se(streq(name, "div"));

        name = mfree(name);
        /* class */
        t = xml_tokenize(&input, &name, &state, NULL);
        assert_se(t == XML_ATTRIBUTE_NAME);
        assert_se(streq(name, "class"));

        name = mfree(name);
        /* "test" */
        t = xml_tokenize(&input, &name, &state, NULL);
        assert_se(t == XML_ATTRIBUTE_VALUE);
        assert_se(streq(name, "test"));

        name = mfree(name);
        /* >text */
        t = xml_tokenize(&input, &name, &state, NULL);
        assert_se(t == XML_TEXT);
        assert_se(streq(name, "text"));

        name = mfree(name);
        /* </div> */
        t = xml_tokenize(&input, &name, &state, NULL);
        assert_se(t == XML_TAG_CLOSE);
        assert_se(streq(name, "div"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
