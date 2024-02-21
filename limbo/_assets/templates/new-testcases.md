<!-- @@new-testcases@@ -->

## New testcases

There are new testcases in this change.

| Testcase | Harness | Expected Result | Actual Result |
| -------- | ------- | --------------- | ------------- |
{% for tc_id, results in new_results.items() %}
{# results is (harness, expected, actual) #}
{% for (harness, expected, actual) in results %}
| `{{ tc_id }}` | {{ harness }} | {{ expected }} | {{ actual }} |
{% endfor %}
{% endfor %}
