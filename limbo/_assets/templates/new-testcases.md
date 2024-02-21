<!-- @@new-testcases@@ -->

## New testcases

There are new testcases in this change.

| Testcase | Harness | Expected Result | Actual Result | Context |
| -------- | ------- | --------------- | ------------- | ------- |
{% for tc_id, results in new_results.items() %}
{# results is (harness, expected, actual) #}
{% for (harness, expected, actual, context) in results %}
| `{{ tc_id }}` | {{ harness }} | {{ expected }} | {{ actual }} | {{ context }} |
{% endfor %}
{% endfor %}
