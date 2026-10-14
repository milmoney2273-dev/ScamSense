import unittest

from app import analyze_message


class ScamSenseTests(unittest.TestCase):


    def test_urgent_message_is_flagged(self):

        result = analyze_message(
            "URGENT: Your account will be blocked. Act now."
        )

        titles = [
            signal["title"]
            for signal in result["signals"]
        ]

        self.assertIn(
            "Urgency or pressure",
            titles
        )


    def test_sensitive_request_is_flagged(self):

        result = analyze_message(
            "Please send your password and OTP "
            "to verify your account."
        )

        titles = [
            signal["title"]
            for signal in result["signals"]
        ]

        self.assertIn(
            "Sensitive information mentioned",
            titles
        )


    def test_payment_pressure_is_flagged(self):

        result = analyze_message(
            "You have won a prize. "
            "Pay a fee to claim your prize."
        )

        titles = [
            signal["title"]
            for signal in result["signals"]
        ]

        self.assertIn(
            "Payment or prize pressure",
            titles
        )


    def test_score_is_within_range(self):

        result = analyze_message(
            "URGENT! Send money and share "
            "your OTP immediately."
        )

        self.assertGreaterEqual(
            result["risk_score"],
            0
        )

        self.assertLessEqual(
            result["risk_score"],
            100
        )


    def test_empty_message_is_rejected(self):

        with self.assertRaises(
            ValueError
        ):

            analyze_message("")


    def test_ordinary_message_is_not_high(self):

        result = analyze_message(
            "Hi, are we still meeting "
            "at the library tomorrow?"
        )

        self.assertLess(
            result["risk_score"],
            50
        )


    def test_http_ip_link_is_flagged(self):

        result = analyze_message(
            "Please visit "
            "http://192.168.1.1/login"
        )

        titles = [
            signal["title"]
            for signal in result["signals"]
        ]

        self.assertIn(
            "Message contains a link",
            titles
        )

        self.assertIn(
            "URL warning",
            titles
        )


    def test_shortened_link_is_flagged(self):

        result = analyze_message(
            "Check this link "
            "https://bit.ly/example"
        )

        explanations = [
            signal["explanation"].lower()
            for signal in result["signals"]
        ]

        self.assertTrue(
            any(
                "shortening service"
                in explanation

                for explanation
                in explanations
            )
        )


    def test_brand_impersonation_domain(self):

        result = analyze_message(
            "Verify your account at "
            "https://paypal-security-example.com/login"
        )

        explanations = [
            signal["explanation"].lower()
            for signal in result["signals"]
        ]

        self.assertTrue(
            any(
                "paypal"
                in explanation

                for explanation
                in explanations
            )
        )


    def test_deep_subdomain_is_flagged(self):

        result = analyze_message(
            "Visit "
            "https://login.account.security.example.com"
        )

        explanations = [
            signal["explanation"].lower()
            for signal in result["signals"]
        ]

        self.assertTrue(
            any(
                "subdomain"
                in explanation

                for explanation
                in explanations
            )
        )


if __name__ == "__main__":

    unittest.main()