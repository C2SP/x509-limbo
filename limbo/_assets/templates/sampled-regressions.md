<!-- @@sampled-regressions@@ -->

{% for harness, regressions in sampled_regressions.items() %}
## {{ harness }}

{% for tc, prev, curr in regressions %}
* {{ testcase_link(tc) }} went from {{ prev.value }} to {{ curr.value }}
{% endfor %}
{% endfor%}
