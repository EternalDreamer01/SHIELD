#!/usr/bin/env python3
################################################################################
# @file      import-cwe-mitigations.py
# @brief     
# @date      Fr Sep 2026
# @author    Dimitri Simon
# 
# PROJECT:   NIST
# 
# MODIFIED:  Fri Sep 11 2026
# BY:        Dimitri Simon
# 
# Copyright (c) 2026 Dimitri Simon
# 
################################################################################

import csv, sys, re


def parse_mitigations(mitigation_text):
    if not mitigation_text:
        return []

    mitigations = []

    # Split the value into separate PHASE blocks
    blocks = re.split(r"::PHASE:", mitigation_text)

    for block in blocks[1:]:
        block = block.rstrip(":")

        # Split into phase, strategy, and description
        parts = re.split(
            r":(STRATEGY|DESCRIPTION):",
            block,
            flags=re.DOTALL
        )

        mitigation = {
            "phase": parts[0].strip(),
            "strategy": "",
            "description": ""
        }

        for index in range(1, len(parts), 2):
            field_name = parts[index]
            field_value = parts[index + 1].strip()

            if field_name == "STRATEGY":
                mitigation["strategy"] = field_value
            elif field_name == "DESCRIPTION":
                mitigation["description"] = field_value

        mitigations.append(mitigation)

    return mitigations


def normalize(value):
    """
    Makes duplicate detection insensitive to extra spaces,
    tabs, and line breaks.
    """
    return re.sub(r"\s+", " ", value).strip()

if __name__ == "__main__":
	input_file = sys.argv[1] if len(sys.argv) > 1 else "data/NIST/cwe.csv"
	output_file = sys.argv[2] if len(sys.argv) > 2 else "data/NIST/cwe_mitigation.csv"

	with open(input_file, "r", newline="", encoding="utf-8-sig") as infile, \
		open(output_file, "w", newline="", encoding="utf-8") as outfile:

		reader = csv.DictReader(infile)
		writer = csv.writer(outfile)

		cwe_column = reader.fieldnames[0]

		writer.writerow([
			"CWE-ID",
			"phase",
			"strategy",
			"description"
		])

		# Stores rows that have already been written
		seen_rows = set()

		for row in reader:
			cwe_id = row[cwe_column].strip()
			mitigation_text = row.get("Potential Mitigations", "")

			parsed_mitigations = parse_mitigations(mitigation_text)

			for mitigation in parsed_mitigations:
				output_row = [
					cwe_id,
					mitigation["phase"],
					mitigation["strategy"],
					# mitigation["description"]
				]

				# Create a normalized version for duplicate detection
				duplicate_key = tuple(normalize(value) for value in output_row)

				if duplicate_key in seen_rows:
					continue

				seen_rows.add(duplicate_key)
				writer.writerow(output_row)
