<!-- @@new-testcases@@ -->

## New testcases

There are new testcases in this change.

| Testcase | Harness | Expected Result | Actual Result |
| -------- | ------- | --------------- | ------------- |
{% for tc_id, (harness, expected, actual) in new_results.items() %}
{# results is (harness, expected, actual) #}
| `{{ tc_id }}` | {{ harness }} | {{ expected }} | {{ actual }} |
{% endfor %}
