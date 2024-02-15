"""
Markdown helpers.
"""

from limbo.models import TestCaseID

BASE_URL = "https://x509-limbo.com"


def testcase_url(testcase_id: TestCaseID) -> str:
    namespace, _ = testcase_id.split("::", 1)
    slug = testcase_id.replace("::", "")
    return f"{BASE_URL}/testcases/{namespace}/#{slug}"


def testcase_link(testcase_id: TestCaseID) -> str:
    url = testcase_url(testcase_id)

    return f"[`{testcase_id}`]({url})"
