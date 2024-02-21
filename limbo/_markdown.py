"""
Markdown helpers.
"""

from jinja2 import Environment, PackageLoader, Template, select_autoescape

from limbo.assets import ASSETS_PATH
from limbo.models import TestCaseID

BASE_URL = "https://x509-limbo.com"

env = Environment(
    trim_blocks=True,
    lstrip_blocks=True,
    autoescape=select_autoescape(),
    loader=PackageLoader(ASSETS_PATH, "templates"),
)


def testcase_url(testcase_id: TestCaseID) -> str:
    namespace, _ = testcase_id.split("::", 1)
    slug = testcase_id.replace("::", "")
    return f"{BASE_URL}/testcases/{namespace}/#{slug}"


def testcase_link(testcase_id: TestCaseID) -> str:
    url = testcase_url(testcase_id)

    return f"[`{testcase_id}`]({url})"


def template(name: str) -> Template:
    return env.get_template(name)
