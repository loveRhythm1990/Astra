"""Ensure synthetic compatibility diagnostics do not expose secrets or locations."""

import unittest

from client_compatibility import safe_error_summary


class CompatibilityDiagnosticsTests(unittest.TestCase):
    def test_errors_keep_the_reason_but_redact_credentials_and_locations(self):
        secret = "fixture-secret-value-which-must-never-be-retained"
        message = (
            "API error (422): unsupported request field; "
            f'Authorization: Bearer {secret}; password="short-secret"; '
            '"api_key": "short-key"; '
            "https://fixture.invalid/private?token=hidden; "
            "/home/fixture/private-file; C:\\fixture\\private-file; "
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiJmaXh0dXJlIn0.signature"
        )
        summary = safe_error_summary(message)
        self.assertIn("API error (422): unsupported request field", summary)
        for forbidden in (
            secret, "short-secret", "short-key", "fixture.invalid", "private-file",
            "eyJhbGciOiJub25lIn0", "eyJzdWIiOiJmaXh0dXJlIn0",
        ):
            self.assertNotIn(forbidden, summary)

    def test_summary_is_bounded_and_does_not_accept_structured_raw_responses(self):
        self.assertIsNone(safe_error_summary({"error": "untrusted body"}))
        self.assertLessEqual(len(safe_error_summary("safe diagnostic " * 300)), 1024)


if __name__ == "__main__":
    unittest.main()
