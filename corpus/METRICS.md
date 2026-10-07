# Detection performance on a labelled corpus

Run 2026-10-07 against the SpamAssassin public corpus (2750 legitimate messages, 1896 spam). Rules only - no model call, no RDAP lookup.

## False positives - the number that matters

Out of real, legitimate mail, how often would this tool disturb an analyst?

| | count | rate |
| --- | ---: | ---: |
| Legitimate messages scored | 2750 | |
| Wrongly labelled **phishing** | 0 | **0.00%** |
| Wrongly labelled suspicious | 0 | 0.00% |
| Correctly left clean | 2750 | 100.00% |

A tool that quarantines real invoices gets switched off in a week, so the
phishing-level false positive rate of **0.00%** is the figure to judge
this on.

## Detection on the spam set - read the caveat

| | count | rate |
| --- | ---: | ---: |
| Spam messages scored | 1896 | |
| Labelled phishing | 0 | 0.00% |
| Labelled suspicious | 4 | 0.21% |
| Flagged at all | 4 | 0.21% |

**Spam is not phishing.** Most of this set is commercial junk with no
credential-theft attempt, which this tool is not built to catch and does
not claim to. The figure understates detection against real phishing and
is reported here only because hiding it would be worse.

## Which rules fired

| rule | on legitimate mail | on spam |
| --- | ---: | ---: |
| `LINK_TEXT_MISMATCH` | 82 | 25 |
| `REPLY_TO_MISMATCH` | 542 | 249 |

## What this corpus actually validated

Not detection - the weights. Each rule's firing rate on **legitimate**
mail is its false positive rate in isolation, and that is the number that
decides what a rule may be worth:

| rule | fires on legit mail | weight | if it were weighted to condemn alone |
| --- | ---: | ---: | --- |
| `REPLY_TO_MISMATCH` | 542 (19.7%) | 15 | 19.7% of legitimate mail flagged |
| `LINK_TEXT_MISMATCH` | 82 (3.0%) | 30 | 3.0% of legitimate mail flagged |

The reply-to check is the clearest case. It fires on roughly one in five
legitimate messages - mailing lists, ticketing systems and support desks
all redirect replies legitimately. It is weighted 15, well below the
suspicious threshold, so on its own it never flags anything. Had it been
weighted at 40 on intuition, this run says a fifth of real mail would have
been pushed into an analyst's queue.

That is what the corpus was good for: not proving the tool catches
phishing, but proving the weights do not catch everything else.

## Limitations, stated plainly

- The corpus dates from 2002-2005, before SPF, DKIM and DMARC were in use.
  Those messages carry no `Authentication-Results` header, so rule 1 and
  the domain-age rule never fire. What is measured here is really rules 2
  and 3 - lookalike domains and deceptive links - plus the reply-to check.
- No public corpus of modern, authenticated phishing exists that can be
  redistributed, which is why this measurement is the one available rather
  than the one wanted.
- **Detection against this spam set is near zero, and that is expected.**
  The tool looks for credential phishing: impersonated brands, forged
  authentication, links that lie. This corpus is commercial junk mail from
  2003. Reporting a detection rate here at all would be measuring the tool
  against a job it does not claim to do.
- The false positive rate below is therefore **flattered**: the rules most
  likely to misfire on real mail - the authentication checks - cannot fire
  on a corpus with no authentication headers. A 0% false positive rate on
  this data is not a claim that the tool has a 0% false positive rate.
- Thresholds at the time of this run: suspicious at 35, phishing at 70.
- 1 messages failed to parse and were excluded.

Reproduce:

    python -m corpus.fetch
    python -m corpus.evaluate --report
