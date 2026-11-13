import os
import unittest

from parsing_engine import extract_domain
from parsing_engine import extract_url
from parsing_engine import get_domain_from_url
from parsing_engine import is_ip_address
from parsing_engine import get_domain_core
from parsing_engine import string_similarity
from parsing_engine import extract_display_name
from parsing_engine import detect_display_name_spoofing
from parsing_engine import detect_link_domain_mismatch
from parsing_engine import parse_email_file
from parsing_engine import parse_email_bytes
from parsing_engine import read_msg
from parsing_engine import extract_attachments


PLAIN_EMAIL = """From: nick@example.com
To: chris@example.com
Subject: Hello

This is the body.
"""

HTML_EMAIL = """From: <nick@example.com>
To: <chris@example.com>
Subject: Hello
Content-Type: text/html

<p>Hi there</p>
"""

EMAIL_WITH_ATTACHMENT = """From: nick@example.com
To: chris@example.com
Subject: Invoice
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY"

--BOUNDARY
Content-Type: text/plain

See attached file.
--BOUNDARY
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.exe"
Content-Transfer-Encoding: base64

TVo=
--BOUNDARY--
"""

EMAIL_WITH_TWO_ATTACHMENTS = """From: nick@example.com
To: chris@example.com
Subject: Files
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY"

--BOUNDARY
Content-Type: text/plain

Two files attached.
--BOUNDARY
Content-Type: application/pdf
Content-Disposition: attachment; filename="report.pdf"
Content-Transfer-Encoding: base64

JVBERg==
--BOUNDARY
Content-Type: application/zip
Content-Disposition: attachment; filename="data.zip"
Content-Transfer-Encoding: base64

UEs=
--BOUNDARY--
"""

EMAIL_ATTACHMENT_NO_NAME = """From: nick@example.com
Subject: Mystery
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY"

--BOUNDARY
Content-Type: text/plain

Hello
--BOUNDARY
Content-Type: application/octet-stream
Content-Disposition: attachment
Content-Transfer-Encoding: base64

TVo=
--BOUNDARY--
"""

EMAIL_PLAIN_AND_HTML = """From: nick@example.com
To: chris@example.com
Subject: Both
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="BOUNDARY"

--BOUNDARY
Content-Type: text/plain

plain version
--BOUNDARY
Content-Type: text/html

<p>html version</p>
--BOUNDARY--
"""

class TestExtractDomain(unittest.TestCase):

    def test_normal_email(self):
        self.assertEqual(extract_domain("chris@example.com"), "example.com")

    def test_uppercase_becomes_lowercase(self):
        self.assertEqual(extract_domain("Chris@EXAMPLE.COM"), "example.com")

    def test_email_with_display_name(self):
        self.assertEqual(extract_domain('"PayPal Security" <security@paypal.com>'), "paypal.com")

    def test_subdomain(self):
        self.assertEqual(extract_domain("nick@mail.example.com"), "mail.example.com")

    def test_empty_string(self):
        self.assertEqual(extract_domain(""), "")

    def test_none(self):
        self.assertEqual(extract_domain(None), "")

    def test_no_at_sign(self):
        self.assertEqual(extract_domain("hello world"), "")


class TestExtractUrl(unittest.TestCase):

    def test_one_http_url(self):
        result = extract_url("go to http://example.com now")
        self.assertEqual(result, ["http://example.com"])

    def test_one_https_url(self):
        result = extract_url("go to https://example.com/login now")
        self.assertEqual(result, ["https://example.com/login"])

    def test_www_url(self):
        result = extract_url("visit www.example.com today")
        self.assertEqual(result, ["www.example.com"])

    def test_two_urls(self):
        result = extract_url("http://a.com and https://b.com")
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], "http://a.com")
        self.assertEqual(result[1], "https://b.com")

    def test_url_inside_html_link(self):
        result = extract_url('<a href="https://evil.com/login">click</a>')
        self.assertEqual(result, ["https://evil.com/login"])

    def test_url_inside_parentheses(self):
        result = extract_url("(https://example.com/page)")
        self.assertEqual(result, ["https://example.com/page"])

    def test_no_url(self):
        self.assertEqual(extract_url("there is no link here"), [])

    def test_empty_string(self):
        self.assertEqual(extract_url(""), [])

    def test_none(self):
        self.assertEqual(extract_url(None), [])


class TestGetDomainFromUrl(unittest.TestCase):

    def test_https_url(self):
        self.assertEqual(get_domain_from_url("https://example.com/page"), "example.com")

    def test_http_url(self):
        self.assertEqual(get_domain_from_url("http://example.com"), "example.com")

    def test_www_is_removed(self):
        self.assertEqual(get_domain_from_url("https://www.example.com"), "example.com")

    def test_url_without_scheme(self):
        self.assertEqual(get_domain_from_url("www.example.com/login"), "example.com")

    def test_uppercase_url(self):
        self.assertEqual(get_domain_from_url("HTTP://EXAMPLE.COM"), "example.com")

    def test_url_with_port(self):
        self.assertEqual(get_domain_from_url("https://example.com:8080/page"), "example.com")

    def test_ip_address_url(self):
        self.assertEqual(get_domain_from_url("http://192.168.1.1/login"), "192.168.1.1")

    def test_subdomain_is_kept(self):
        self.assertEqual(get_domain_from_url("https://login.example.com"), "login.example.com")

    def test_empty_string(self):
        self.assertEqual(get_domain_from_url(""), "")



class TestIsIpAddress(unittest.TestCase):

    def test_real_ip(self):
        self.assertTrue(is_ip_address("192.168.1.1"))

    def test_all_zeros(self):
        self.assertTrue(is_ip_address("0.0.0.0"))

    def test_max_ip(self):
        self.assertTrue(is_ip_address("255.255.255.255"))

    def test_number_too_big(self):
        self.assertFalse(is_ip_address("256.1.1.1"))

    def test_too_few_parts(self):
        self.assertFalse(is_ip_address("1.2.3"))

    def test_too_many_parts(self):
        self.assertFalse(is_ip_address("1.2.3.4.5"))

    def test_domain_name(self):
        self.assertFalse(is_ip_address("example.com"))

    def test_empty_string(self):
        self.assertFalse(is_ip_address(""))



class TestGetDomainCore(unittest.TestCase):

    def test_simple_domain(self):
        self.assertEqual(get_domain_core("paypal.com"), "paypal")

    def test_subdomain(self):
        self.assertEqual(get_domain_core("mail.google.com"), "google")

    def test_hyphen(self):
        self.assertEqual(get_domain_core("paypall-alerts.com"), "paypall")

    def test_uppercase(self):
        self.assertEqual(get_domain_core("PayPal.COM"), "paypal")

    def test_one_word_domain(self):
        self.assertEqual(get_domain_core("localhost"), "localhost")

    def test_empty_string(self):
        self.assertEqual(get_domain_core(""), "")



class TestStringSimilarity(unittest.TestCase):

    def test_same_strings(self):
        self.assertEqual(string_similarity("paypal", "paypal"), 1.0)

    def test_totally_different_strings(self):
        self.assertEqual(string_similarity("abc", "def"), 0.0)

    def test_first_string_empty(self):
        self.assertEqual(string_similarity("", "paypal"), 0.0)

    def test_second_string_empty(self):
        self.assertEqual(string_similarity("paypal", ""), 0.0)

    def test_both_empty(self):
        self.assertEqual(string_similarity("", ""), 0.0)

    def test_similar_strings(self):
        score = string_similarity("paypal", "paypall")
        self.assertTrue(score > 0.9)
        self.assertTrue(score < 1.0)

    def test_different_lengths(self):
        score = string_similarity("pay", "paypal")
        self.assertTrue(score > 0.0)
        self.assertTrue(score < 1.0)



class TestExtractDisplayName(unittest.TestCase):

    def test_name_in_quotes(self):
        self.assertEqual(extract_display_name('"PayPal Security" <security@paypal.com>'), "PayPal Security")

    def test_name_without_quotes(self):
        self.assertEqual(extract_display_name("Nick Fury <nick@example.com>"), "Nick Fury")

    def test_only_email_in_brackets(self):
        self.assertEqual(extract_display_name("chris@example.com"), "")

    def test_only_email(self):
        self.assertEqual(extract_display_name("chris@example.com"), "")

    def test_empty_string(self):
        self.assertEqual(extract_display_name(""), "")

    def test_none(self):
        self.assertEqual(extract_display_name(None), "")


class TestDetectDisplayNameSpoofing(unittest.TestCase):

    def test_real_paypal_email(self):
        result = detect_display_name_spoofing('"PayPal Security" <security@paypal.com>')
        self.assertEqual(result["status"], "consistent")

    def test_real_paypal_email_details(self):
        result = detect_display_name_spoofing('"PayPal Security" <security@paypal.com>')
        self.assertEqual(result["display_name"], "PayPal Security")
        self.assertEqual(result["claimed_brand"], "paypal")
        self.assertEqual(result["domain"], "paypal.com")
        self.assertEqual(result["domain_core"], "paypal")
        self.assertEqual(result["similarity"], 1.0)

    def test_fake_paypal_with_two_ls(self):
        result = detect_display_name_spoofing('"PayPal Security" <security@paypall.com>')
        self.assertEqual(result["status"], "typosquat")

    def test_fake_paypal_similarity_score(self):
        result = detect_display_name_spoofing('"PayPal Security" <security@paypall.com>')
        self.assertEqual(result["similarity"], 0.92)

    def test_fake_amazon_with_zero(self):
        result = detect_display_name_spoofing('"Amazon Billing" <billing@amaz0n.com>')
        self.assertEqual(result["status"], "typosquat")

    def test_fake_paypal_with_hyphen(self):
        result = detect_display_name_spoofing('"PayPal Security" <alerts@paypall-alerts.com>')
        self.assertEqual(result["status"], "typosquat")

    def test_unrelated_domain(self):
        result = detect_display_name_spoofing('"PayPal Security" <alerts@random-shop.com>')
        self.assertEqual(result["status"], "unrelated")

    def test_normal_person_name(self):
        result = detect_display_name_spoofing('"Chris Evans" chris@example.com')
        self.assertEqual(result["status"], "none")

    def test_only_generic_words(self):
        result = detect_display_name_spoofing('"Support Team" <help@example.com>')
        self.assertEqual(result["status"], "none")
        self.assertEqual(result["claimed_brand"], "")

    def test_no_display_name(self):
        result = detect_display_name_spoofing("billing@paypal.com")
        self.assertEqual(result["status"], "none")
        self.assertEqual(result["display_name"], "")

    def test_uppercase_still_works(self):
        result = detect_display_name_spoofing('"PAYPAL SECURITY" <x@PAYPAL.COM>')
        self.assertEqual(result["status"], "consistent")

    def test_subdomain_of_real_brand(self):
        result = detect_display_name_spoofing('"Google Support" <no-reply@accounts.google.com>')
        self.assertEqual(result["status"], "consistent")

    def test_empty_string(self):
        result = detect_display_name_spoofing("")
        self.assertEqual(result["status"], "none")

    def test_none(self):
        result = detect_display_name_spoofing(None)
        self.assertEqual(result["status"], "none")


class TestDetectLinkDomainMismatch(unittest.TestCase):

    def test_typosquat_link(self):
        result = detect_link_domain_mismatch("paypall.com", "paypal.com")
        self.assertEqual(result[0], "typosquat")

    def test_typosquat_link_score(self):
        result = detect_link_domain_mismatch("paypall.com", "paypal.com")
        self.assertEqual(result[1], 0.92)

    def test_number_instead_of_letter(self):
        result = detect_link_domain_mismatch("paypa1.com", "paypal.com")
        self.assertEqual(result[0], "typosquat")

    def test_same_domain(self):
        result = detect_link_domain_mismatch("paypal.com", "paypal.com")
        self.assertEqual(result, ("none", 0.0))

    def test_subdomain_of_same_domain(self):
        result = detect_link_domain_mismatch("login.paypal.com", "paypal.com")
        self.assertEqual(result, ("none", 0.0))

    def test_totally_different_domain(self):
        result = detect_link_domain_mismatch("evil.com", "paypal.com")
        self.assertEqual(result[0], "none")

    def test_empty_link_domain(self):
        result = detect_link_domain_mismatch("", "paypal.com")
        self.assertEqual(result, ("none", 0.0))

    def test_empty_sender_domain(self):
        result = detect_link_domain_mismatch("paypal.com", "")
        self.assertEqual(result, ("none", 0.0))


class TestParseEmailBytes(unittest.TestCase):

    def test_subject(self):
        msg = parse_email_bytes(PLAIN_EMAIL.encode())
        self.assertEqual(msg["Subject"], "Hello")

    def test_from(self):
        msg = parse_email_bytes(PLAIN_EMAIL.encode())
        self.assertEqual(str(msg["From"]), "nick@example.com")

    def test_to(self):
        msg = parse_email_bytes(PLAIN_EMAIL.encode())
        self.assertEqual(str(msg["To"]), "chris@example.com")

    def test_missing_header_is_none(self):
        msg = parse_email_bytes(PLAIN_EMAIL.encode())
        self.assertIsNone(msg["X-Fake-Header"])

    def test_empty_bytes(self):
        msg = parse_email_bytes(b"")
        self.assertIsNone(msg["Subject"])


class TestParseEmailFile(unittest.TestCase):

    def setUp(self):
        f = open("temp_test_email.eml", "w")
        f.write(PLAIN_EMAIL)
        f.close()

    def tearDown(self):
        os.remove("temp_test_email.eml")

    def test_reads_subject(self):
        msg = parse_email_file("temp_test_email.eml")
        self.assertEqual(msg["Subject"], "Hello")

    def test_reads_body(self):
        msg = parse_email_file("temp_test_email.eml")
        plaintext, html = read_msg(msg)
        self.assertIn("This is the body.", plaintext)

    def test_file_that_does_not_exist(self):
        with self.assertRaises(FileNotFoundError):
            parse_email_file("this_file_is_not_here.eml")


class TestReadMsg(unittest.TestCase):

    def test_plain_email_plaintext(self):
        msg = parse_email_bytes(PLAIN_EMAIL.encode())
        plaintext, _html = read_msg(msg)
        self.assertIn("This is the body.", plaintext)

    def test_plain_email_has_no_html(self):
        msg = parse_email_bytes(PLAIN_EMAIL.encode())
        _plaintext, html = read_msg(msg)
        self.assertEqual(html, "")

    def test_html_email_html(self):
        msg = parse_email_bytes(HTML_EMAIL.encode())
        _plaintext, html = read_msg(msg)
        self.assertIn("<p>Hi there</p>", html)

    def test_html_email_has_no_plaintext(self):
        msg = parse_email_bytes(HTML_EMAIL.encode())
        plaintext, _html = read_msg(msg)
        self.assertEqual(plaintext, "")

    def test_plain_and_html_email_plaintext(self):
        msg = parse_email_bytes(EMAIL_PLAIN_AND_HTML.encode())
        plaintext, _html = read_msg(msg)
        self.assertIn("plain version", plaintext)

    def test_plain_and_html_email_html(self):
        msg = parse_email_bytes(EMAIL_PLAIN_AND_HTML.encode())
        _plaintext, html = read_msg(msg)
        self.assertIn("html version", html)

    def test_email_with_attachment_still_reads_body(self):
        msg = parse_email_bytes(EMAIL_WITH_ATTACHMENT.encode())
        plaintext, _html = read_msg(msg)
        self.assertIn("See attached file.", plaintext)

    def test_returns_two_things(self):
        msg = parse_email_bytes(PLAIN_EMAIL.encode())
        result = read_msg(msg)
        self.assertEqual(len(result), 2)


class TestExtractAttachments(unittest.TestCase):

    def test_no_attachments(self):
        msg = parse_email_bytes(PLAIN_EMAIL.encode())
        self.assertEqual(extract_attachments(msg), [])

    def test_html_email_has_no_attachments(self):
        msg = parse_email_bytes(HTML_EMAIL.encode())
        self.assertEqual(extract_attachments(msg), [])

    def test_plain_and_html_email_has_no_attachments(self):
        msg = parse_email_bytes(EMAIL_PLAIN_AND_HTML.encode())
        self.assertEqual(extract_attachments(msg), [])

    def test_one_attachment_count(self):
        msg = parse_email_bytes(EMAIL_WITH_ATTACHMENT.encode())
        result = extract_attachments(msg)
        self.assertEqual(len(result), 1)

    def test_one_attachment_filename(self):
        msg = parse_email_bytes(EMAIL_WITH_ATTACHMENT.encode())
        result = extract_attachments(msg)
        self.assertEqual(result[0]["filename"], "invoice.exe")

    def test_one_attachment_type(self):
        msg = parse_email_bytes(EMAIL_WITH_ATTACHMENT.encode())
        result = extract_attachments(msg)
        self.assertEqual(result[0]["type"], "application/octet-stream")

    def test_two_attachments_count(self):
        msg = parse_email_bytes(EMAIL_WITH_TWO_ATTACHMENTS.encode())
        result = extract_attachments(msg)
        self.assertEqual(len(result), 2)

    def test_two_attachments_names_in_order(self):
        msg = parse_email_bytes(EMAIL_WITH_TWO_ATTACHMENTS.encode())
        result = extract_attachments(msg)
        self.assertEqual(result[0]["filename"], "report.pdf")
        self.assertEqual(result[1]["filename"], "data.zip")

    def test_attachment_without_a_filename(self):
        msg = parse_email_bytes(EMAIL_ATTACHMENT_NO_NAME.encode())
        result = extract_attachments(msg)
        self.assertEqual(result[0]["filename"], "unknown")


if __name__ == "__main__":
    unittest.main()