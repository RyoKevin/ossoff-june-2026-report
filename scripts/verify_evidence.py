#!/usr/bin/env python3
"""Offline checks of published aggregates, README numbers, and SHA-256 bytes.

Python 3.9+, standard library only. This does not rebuild the FEC transaction set.
"""

import argparse
import hashlib
import json
import math
import re
import sys
from decimal import Decimal, ROUND_HALF_UP
from fractions import Fraction
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_FILES = (
    "national.json", "donor_history.json", "state_comparison.json",
    "geography.json", "public_sources.json",
)
REQUIRED_HASHES = {"README.md"} | {"evidence/" + name for name in EVIDENCE_FILES}
PERIODS = ("June1_28", "June29", "June30")  # June23_28 overlaps the baseline.
STATES = set((
    "AL AK AZ AR CA CO CT DE DC FL GA HI ID IL IN IA KS KY LA ME MD MA MI "
    "MN MS MO MT NE NV NH NJ NM NY NC ND OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY"
).split())


class VerificationError(ValueError):
    """A missing, malformed, or inconsistent published value."""


class Audit:
    def __init__(self):
        self.checks = 0

    def require(self, condition, label):
        if not condition:
            raise VerificationError(label)
        self.checks += 1

    def equal(self, actual, expected, label):
        self.require(actual == expected, f"{label}: got {actual!r}, expected {expected!r}")

    def near(self, actual, expected, label):
        self.require(
            type(actual) in (int, float) and math.isfinite(actual)
            and math.isclose(actual, float(expected), rel_tol=1e-12, abs_tol=1e-10),
            f"{label}: stored rate disagrees with counts",
        )


def count(value):
    if type(value) is not int or value < 0:
        raise VerificationError("Counts must be nonnegative integers")
    return value


def percent(numerator, denominator):
    numerator, denominator = count(numerator), count(denominator)
    if denominator == 0 or numerator > denominator:
        raise VerificationError("Rate needs a positive denominator and numerator <= denominator")
    return 100 * Fraction(numerator, denominator)


def display(value, places=2):
    value = Fraction(value)
    number = Decimal(value.numerator) / Decimal(value.denominator)
    return format(number.quantize(Decimal(1).scaleb(-places), rounding=ROUND_HALF_UP), f".{places}f")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise VerificationError(f"Non-finite JSON number: {value}")


def load_evidence(root):
    return {
        name[:-5]: json.loads(
            (root / "evidence" / name).read_text(encoding="utf-8"),
            object_pairs_hook=unique_object, parse_constant=reject_constant,
        )
        for name in EVIDENCE_FILES
    }


def verify_checksums(root):
    """Check every manifest entry, including coverage of the original six files."""
    audit, seen = Audit(), set()
    for line_no, line in enumerate((root / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines(), 1):
        match = re.fullmatch(r"([0-9a-fA-F]{64}) [ *](.+)", line)
        audit.require(match is not None, f"Malformed SHA256SUMS.txt line {line_no}")
        digest, name = match.groups()
        path = PurePosixPath(name)
        audit.require(
            not path.is_absolute() and ".." not in path.parts and "\\" not in name
            and str(path) == name and name != "SHA256SUMS.txt",
            f"Invalid checksum path at line {line_no}",
        )
        audit.require(name not in seen, f"Duplicate checksum entry: {name}")
        seen.add(name)
        target = root / name
        audit.require(target.resolve().is_relative_to(root.resolve()), f"Checksum path escapes root: {name}")
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        audit.equal(actual, digest.lower(), f"SHA-256 {name}")
    audit.require(REQUIRED_HASHES <= seen, "Checksum manifest omits README or an evidence file")
    return len(seen)


def table(readme, section):
    match = re.search(r"^## " + re.escape(section) + r"\s*\n(.*?)(?=^## |\Z)", readme, re.M | re.S)
    if match is None:
        raise VerificationError(f"README section missing: {section}")
    rows = {}
    for line in match.group(1).splitlines():
        if line.startswith("|"):
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if re.fullmatch(r":?-+:?", cells[0]):
                continue
            if cells[0] in rows:
                raise VerificationError(f"Duplicate README row: {cells[0]}")
            rows[cells[0]] = cells[1:]
    return rows


def narrative(audit, readme, pattern, values, label):
    matches = list(re.finditer(pattern, readme))
    audit.require(bool(matches), f"README claim missing: {label}")
    for match in matches:
        audit.equal(list(match.groups()), [str(v) for v in values], f"README {label}")


def verify_statistics(root):
    data, audit = load_evidence(root), Audit()
    readme = (root / "README.md").read_text(encoding="utf-8").replace("**", "")
    national = data["national"]

    def share(row, label):
        rate = percent(row.get("2700", 0), row["transactions"])
        audit.near(row["p27_pct"], rate, label + " p27_pct")
        audit.near(row["p27_small_pct"], percent(row.get("2700", 0), row["small_transactions"]), label + " p27_small_pct")
        audit.require(row["small_transactions"] <= row["transactions"], label + " small <= total")
        return rate

    for period, recipients in national["periods"].items():
        for recipient, row in recipients.items():
            share(row, f"{period}/{recipient}")

    rows = table(readme, "两天形成全月27美元交易的主峰")
    rates = {}
    for period, label in zip(PERIODS, ("6月1—28日", "6月29日", "6月30日")):
        pair = national["periods"][period]
        row, other = pair["ossoff"], pair["all_other_earmarked_recipients"]
        rates[period] = percent(row.get("2700", 0), row["transactions"])
        audit.equal(rows.get(label), [f'{row.get("2700", 0):,}', f'{row["transactions"]:,}',
                    display(rates[period], 3) + "%", display(percent(other["2700"], other["transactions"]), 3) + "%"],
                    "README period table " + label)

    month_tx = sum(count(national["periods"][p]["ossoff"]["transactions"]) for p in PERIODS)
    month_27 = sum(count(national["periods"][p]["ossoff"]["2700"]) for p in PERIODS)
    late_tx = sum(national["periods"][p]["ossoff"]["transactions"] for p in PERIODS[1:])
    late_27 = sum(national["periods"][p]["ossoff"]["2700"] for p in PERIODS[1:])
    if not rates["June1_28"]:
        raise VerificationError("Baseline 27-dollar share is zero; multiplier is undefined")
    multiplier = rates["June30"] / rates["June1_28"]
    change = rates["June30"] - rates["June1_28"]
    narrative(audit, readme, r"最后两天产生\s*([\d,]+)笔27美元交易，占全月([\d,]+)笔的\s*([\d.]+)%",
              [f"{late_27:,}", f"{month_27:,}", display(percent(late_27, month_27))], "late 27-dollar concentration")
    narrative(audit, readme, r"同两天的全部交易占全月比例为\s*([\d.]+)%",
              [display(percent(late_tx, month_tx))], "late all-transaction concentration")
    narrative(audit, readme, r"全月近(\d+)%", [display(percent(late_27, month_27), 0)], "rounded headline concentration")
    narrative(audit, readme, r"(?:此前的|基线的)\s*([\d.]+)倍", [display(multiplier)], "June30 multiplier")
    narrative(audit, readme, r"提高\s*([\d.]+)个百分点", [display(change)], "June30 percentage-point change")
    narrative(audit, readme, r"占比从此前28天的([\d.]+)%", [display(rates["June1_28"])], "rounded baseline")
    narrative(audit, readme, r"奥索夫六月共([\d,]+)笔", [f"{month_tx:,}"], "June aggregate total")

    states = national["ossoff_state_comparison"]
    audit.equal({row["state"] for row in states}, STATES, "50 states and DC coverage")
    audit.equal(len(states), len(STATES), "No duplicate state rows")
    for row in states:
        for period in PERIODS:
            share(row[period], row["state"] + "/" + period)
        audit.equal(row["month_transactions"], sum(row[p]["transactions"] for p in PERIODS), "State month cross-foot")
    for period in PERIODS:
        for key in ("transactions", "2700"):
            audit.equal(sum(count(row[period].get(key, 0)) for row in states), national["periods"][period]["ossoff"][key], "State/national cross-foot " + period + "/" + key)
    higher = lambda row, p: percent(row[p].get("2700", 0), row[p]["transactions"]) > percent(row["June1_28"].get("2700", 0), row["June1_28"]["transactions"])
    large = [row for row in states if row["month_transactions"] >= 3000]
    derived = {
        "states_higher_June30_than_June1_28": sum(higher(row, "June30") for row in states),
        "states_with_month_at_least3000": len(large),
        "large_states_higher_June29_than_June1_28": sum(higher(row, "June29") for row in large),
        "large_states_higher_June30_than_June1_28": sum(higher(row, "June30") for row in large),
    }
    audit.equal(derived["states_higher_June30_than_June1_28"], len(STATES), "All states increased on June30")
    audit.require(all(higher(row, p) for row in large for p in PERIODS[1:]), "Both late days increased in every large state")
    narrative(audit, readme, r"固定([\d,]+)个大样本州", [len(large)], "large-state count")

    candidates = national["candidate_comparison"]
    audit.equal(len({row["committee"] for row in candidates}), len(candidates), "Unique candidate committees")
    deltas = {}
    for row in candidates:
        for period in PERIODS:
            share(row[period], row["committee"] + "/" + period)
        audit.require(sum(row[p]["transactions"] for p in PERIODS) >= 20000, "Candidate monthly threshold")
        deltas[row["committee"]] = percent(row["June30"].get("2700", 0), row["June30"]["transactions"]) - percent(row["June1_28"].get("2700", 0), row["June1_28"]["transactions"])
        audit.near(row["share_change_pp"], deltas[row["committee"]], "Candidate share change")
        audit.near(row["total_transactions_June30_to_June29_ratio"], Fraction(row["June30"]["transactions"], row["June29"]["transactions"]), "Candidate volume ratio")
    by_committee = {row["committee"]: row for row in candidates}
    for period in PERIODS:
        audit.equal(by_committee["C00718866"][period], national["periods"][period]["ossoff"], "Ossoff candidate/national agreement")
    audit.equal(max(deltas, key=deltas.get), "C00718866", "Ossoff largest share increase")
    derived["candidates_total_tx_higher_June30_than_June29"] = sum(row["June30"]["transactions"] > row["June29"]["transactions"] for row in candidates)
    derived["candidates_p27_higher_June30_than_June1_28"] = sum(delta > 0 for delta in deltas.values())
    audit.equal(derived["candidates_total_tx_higher_June30_than_June29"], len(candidates), "All candidate volumes increased")
    for key, value in derived.items():
        audit.equal(national["counts"][key], value, "Recount national.counts/" + key)
    narrative(audit, readme, r"在([\d,]+)个六月交易数达到20,000笔", [len(candidates)], "candidate count")
    candidate_rows = table(readme, "共同的季末增量与奥索夫突出的金额变化")
    for label, committee in (("Jon Ossoff", "C00718866"), ("Mark Kelly", "C00696526"), ("Graham Platner", "C00916437"), ("Sherrod Brown", "C00916288"), ("James Talarico", "C00919084"), ("Bernie Sanders", "C00411330")):
        row = by_committee[committee]
        expected = [display(percent(row[p].get("2700", 0), row[p]["transactions"]), 3) + "%" for p in ("June1_28", "June30")]
        expected.append("大幅上升" if committee == "C00718866" else "上升" if deltas[committee] > 0 else "下降")
        audit.equal(candidate_rows.get(label), expected, "README candidate " + label)

    history = data["donor_history"]["late_27"]
    for variant, row in history.items():
        c, categories = row["counts"], row["exclusive_history_categories"]
        audit.equal(sum(count(v) for v in categories.values()), count(c["keys"]), variant + " history categories sum")
        audit.equal(categories["prior_other_27_only"] + categories["prior_ossoff_27"], c["previous_any_recipient_27"], variant + " prior27 categories")
        audit.equal(c["transactions"], late_27, variant + " late27 transactions")
        audit.require(count(c["keys"]) <= c["transactions"], variant + " proxies <= transactions")
        percent(c["july_ossoff_27"], c["july_ossoff_any"])
    c = history["baseline"]["counts"]
    categories = history["baseline"]["exclusive_history_categories"]
    audit.equal(history["strict_address"]["counts"]["keys"], c["keys"], "Strict-address proxy total")
    history_rows = table(readme, "27美元是一批捐款人的短期金额选择")
    for label, n in (("有其他金额历史，没有27美元历史", categories["prior_other_only_other_amount"] + categories["prior_ossoff_other_amount"]), ("曾向可识别收款方捐过27美元", c["previous_any_recipient_27"]), ("回查窗口内未匹配到既往记录", categories["no_prior_identified_earmark"])):
        audit.equal(history_rows.get(label), [f"{n:,}", display(percent(n, c["keys"])) + "%"], "README history " + label)
    audit.equal(history_rows.get("合计"), [f'{c["keys"]:,}', "100%"], "README history total")
    narrative(audit, readme, r"合并为([\d,]+)个姓名邮编代理", [f'{c["keys"]:,}'], "history proxy total")
    july_other = c["july_ossoff_any"] - c["july_ossoff_27"]
    narrative(audit, readme, r"此前向奥索夫捐过27美元的为\s*([\d,]+)个，占([\d.]+)%", [c["previous_ossoff_27"], display(percent(c["previous_ossoff_27"], c["keys"]))], "prior Ossoff27")
    narrative(audit, readme, r"七月仍向奥索夫捐款的([\d,]+)个代理中，([\d,]+)个继续出现27美元记录，\s*([\d,]+)个只出现其他金额，占七月回流者的([\d.]+)%", [c["july_ossoff_any"], c["july_ossoff_27"], july_other, display(percent(july_other, c["july_ossoff_any"]))], "July follow-up")

    comparison = data["state_comparison"]
    repeat_rows = table(readme, "得州与佛州的精确接近集中在六月自然月口径")
    repeat_rates = {}
    for state, label in (("TX", "得州 TX"), ("FL", "佛州 FL"), ("VA", "弗吉尼亚 VA")):
        row = comparison["june_state_totals"][state]
        repeat_rates[state] = percent(row["repeat_proxies"], row["proxies"])
        audit.require(count(row["proxies"]) + count(row["repeat_proxies"]) <= count(row["transactions"]), "Repeat proxy/transaction bound " + state)
        audit.equal(repeat_rows.get(label), [f'{row["transactions"]:,}', f'{row["proxies"]:,}', f'{row["repeat_proxies"]:,}', display(repeat_rates[state], 5) + "%"], "README repeat rate " + state)
        geography = data["geography"]["views"]["all_positive"][state]["totals"]
        audit.equal(row["transactions"], geography["month_tx"], "Geography transaction total " + state)
        audit.equal(row["proxies"], geography["month_donors"], "Geography proxy total " + state)
        state_row = next(row for row in states if row["state"] == state)
        audit.equal(geography["month_tx"], state_row["month_transactions"], "Geography/national cross-foot " + state)
    gap = abs(repeat_rates["TX"] - repeat_rates["FL"])
    narrative(audit, readme, r"得州与佛州只差\s*([\d.]+)个百分点", [display(gap, 5)], "TX-FL repeat gap")
    windows = comparison["adjacent_windows"]
    audit.equal(len(windows), 3, "Three adjacent windows")
    audit.equal({(row["start_date"], row["end_date"]) for row in windows}, {
        ("2026-05-31", "2026-06-29"), ("2026-06-01", "2026-06-30"),
        ("2026-06-02", "2026-07-01"),
    }, "Adjacent window dates")
    for row in windows:
        audit.require(all(len(row[key]) == 2 for key in ("repeat_keys", "proxy_keys", "repeat_pct")), "Window TX/FL array lengths")
        rates_pair = [percent(n, d) for n, d in zip(row["repeat_keys"], row["proxy_keys"])]
        audit.equal(len(rates_pair), 2, "Window TX/FL counts")
        for rate, stored in zip(rates_pair, row["repeat_pct"]):
            audit.near(stored, rate, "Window repeat percentage")
        window_gap = abs(rates_pair[0] - rates_pair[1])
        audit.near(row["repeat_gap_pp"], window_gap, "Window repeat gap")
        start, end = row["start_date"], row["end_date"]
        label = f"{int(start[5:7])}月{int(start[8:])}日—{int(end[5:7])}月{int(end[8:])}日"
        audit.equal(repeat_rows.get(label), [display(window_gap, 5) + "个百分点"], "README adjacent window " + label)

    fl = data["geography"]["views"]["all_positive"]["FL"]
    outside = fl["outside_municipality_name_group"]
    for key in ("before_tx", "day30_tx", "before_27_tx", "day30_27_tx"):
        audit.equal(outside[key], fl["totals"][key] - fl["municipality_name_group"][key], "Florida outside-group subtraction " + key)
    outside_rates = [percent(outside[p + "_27_tx"], outside[p + "_tx"]) for p in ("before", "day30")]
    for key, rate in zip(("outside_group_before", "outside_group_day30"), outside_rates):
        audit.near(fl["27_rate_comparisons_pct"][key], rate, "Florida stored outside-group rate")
    narrative(audit, readme, r"佛州27美元占比仍从6月1—29日的\s*([\d.]+)%上升至30日的\s*([\d.]+)%", [display(v) for v in outside_rates], "Florida outside-group rates")

    return audit.checks, [
        f"27-dollar shares: {', '.join(display(rates[p], 6) + '%' for p in PERIODS)}",
        f"June30/baseline: {display(multiplier, 6)}x; change: {display(change, 6)} pp",
        f"Last two days: {late_27:,}/{month_27:,} = {display(percent(late_27, month_27))}% of 27-dollar transactions",
        f"Last two days: {late_tx:,}/{month_tx:,} = {display(percent(late_tx, month_tx))}% of all transactions",
        f"TX-FL repeat-rate gap: {display(gap, 5)} pp",
    ]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="Repository directory (default: script's parent repository)")
    args = parser.parse_args(argv)
    failed = False
    for label, run in (("SHA-256", verify_checksums), ("Aggregate arithmetic and README", verify_statistics)):
        try:
            result = run(args.root)
            if label == "SHA-256":
                print(f"PASS {label}: {result} files")
            else:
                checks, summary = result
                print(f"PASS {label}: {checks} checks")
                for line in summary:
                    print("  " + line)
        except (OSError, ValueError, KeyError, TypeError, IndexError, StopIteration, ZeroDivisionError) as error:
            print(f"FAIL {label}: {error}", file=sys.stderr)
            failed = True
    print("Scope: published aggregate consistency. FEC row selection, donor matching, and historical form settings require source evidence; see VERIFICATION.md.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
