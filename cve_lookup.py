import requests
import re


# ============================================================
# NVD API
# ============================================================

NVD_API_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)


HEADERS = {
    "User-Agent":
        "Python-Port-Scanner/2.0"
}


# ============================================================
# VERSION PARSING
# ============================================================

def parse_version(version):

    if not version:
        return None

    version = str(version).strip()

    match = re.search(
        r"\d+(?:\.\d+)+",
        version
    )

    if not match:
        return None

    numbers = match.group(0).split(".")

    return tuple(
        int(number)
        for number in numbers
    )


# ============================================================
# COMPARE VERSIONS
# ============================================================

def compare_versions(
    version_a,
    version_b
):

    a = parse_version(version_a)
    b = parse_version(version_b)

    if a is None or b is None:
        return None

    length = max(
        len(a),
        len(b)
    )

    a = a + (
        0,
    ) * (
        length - len(a)
    )

    b = b + (
        0,
    ) * (
        length - len(b)
    )

    if a < b:
        return -1

    if a > b:
        return 1

    return 0


# ============================================================
# VERSION IS IN RANGE
# ============================================================

def version_in_range(
    version,
    start_including=None,
    start_excluding=None,
    end_including=None,
    end_excluding=None
):

    if not version:
        return False

    # --------------------------------------------------------
    # Start inclusive
    # --------------------------------------------------------

    if start_including:

        comparison = compare_versions(
            version,
            start_including
        )

        if comparison is None:
            return False

        if comparison < 0:
            return False

    # --------------------------------------------------------
    # Start exclusive
    # --------------------------------------------------------

    if start_excluding:

        comparison = compare_versions(
            version,
            start_excluding
        )

        if comparison is None:
            return False

        if comparison <= 0:
            return False

    # --------------------------------------------------------
    # End inclusive
    # --------------------------------------------------------

    if end_including:

        comparison = compare_versions(
            version,
            end_including
        )

        if comparison is None:
            return False

        if comparison > 0:
            return False

    # --------------------------------------------------------
    # End exclusive
    # --------------------------------------------------------

    if end_excluding:

        comparison = compare_versions(
            version,
            end_excluding
        )

        if comparison is None:
            return False

        if comparison >= 0:
            return False

    return True


# ============================================================
# EXTRACT DESCRIPTION
# ============================================================

def get_description(cve):

    descriptions = cve.get(
        "descriptions",
        []
    )

    for description in descriptions:

        if description.get(
            "lang"
        ) == "en":

            return description.get(
                "value",
                ""
            )

    return ""


# ============================================================
# EXTRACT CVSS
# ============================================================

def get_cvss(cve):

    metrics = cve.get(
        "metrics",
        {}
    )

    # --------------------------------------------------------
    # CVSS 4.0
    # --------------------------------------------------------

    cvss40 = metrics.get(
        "cvssMetricV40",
        []
    )

    if cvss40:

        data = cvss40[0].get(
            "cvssData",
            {}
        )

        return {

            "version": "4.0",

            "score":
                data.get(
                    "baseScore"
                ),

            "severity":
                data.get(
                    "baseSeverity"
                )
        }

    # --------------------------------------------------------
    # CVSS 3.1
    # --------------------------------------------------------

    cvss31 = metrics.get(
        "cvssMetricV31",
        []
    )

    if cvss31:

        data = cvss31[0].get(
            "cvssData",
            {}
        )

        return {

            "version": "3.1",

            "score":
                data.get(
                    "baseScore"
                ),

            "severity":
                data.get(
                    "baseSeverity"
                )
        }

    # --------------------------------------------------------
    # CVSS 3.0
    # --------------------------------------------------------

    cvss30 = metrics.get(
        "cvssMetricV30",
        []
    )

    if cvss30:

        data = cvss30[0].get(
            "cvssData",
            {}
        )

        return {

            "version": "3.0",

            "score":
                data.get(
                    "baseScore"
                ),

            "severity":
                data.get(
                    "baseSeverity"
                )
        }

    # --------------------------------------------------------
    # CVSS 2.0
    # --------------------------------------------------------

    cvss2 = metrics.get(
        "cvssMetricV2",
        []
    )

    if cvss2:

        data = cvss2[0].get(
            "cvssData",
            {}
        )

        return {

            "version": "2.0",

            "score":
                data.get(
                    "baseScore"
                ),

            "severity":
                None
        }

    return {

        "version": None,

        "score": None,

        "severity": None
    }


# ============================================================
# EXTRACT REFERENCES
# ============================================================

def get_references(cve):

    references = []

    for reference in cve.get(
        "references",
        []
    ):

        url = reference.get(
            "url"
        )

        if url:

            references.append(
                url
            )

    return references


# ============================================================
# EXTRACT CPE MATCHES
# ============================================================

def get_cpe_matches(cve):

    configurations = cve.get(
        "configurations",
        []
    )

    matches = []

    for configuration in configurations:

        nodes = configuration.get(
            "nodes",
            []
        )

        for node in nodes:

            cpe_matches = node.get(
                "cpeMatch",
                []
            )

            for cpe in cpe_matches:

                if not cpe.get(
                    "vulnerable",
                    False
                ):
                    continue

                criteria = cpe.get(
                    "criteria",
                    ""
                )

                matches.append({

                    "criteria":
                        criteria,

                    "versionStartIncluding":
                        cpe.get(
                            "versionStartIncluding"
                        ),

                    "versionStartExcluding":
                        cpe.get(
                            "versionStartExcluding"
                        ),

                    "versionEndIncluding":
                        cpe.get(
                            "versionEndIncluding"
                        ),

                    "versionEndExcluding":
                        cpe.get(
                            "versionEndExcluding"
                        )
                })

    return matches


# ============================================================
# CPE PRODUCT MATCH
# ============================================================

def cpe_matches_product(
    criteria,
    service
):

    if not criteria:
        return False

    if not service:
        return False

    criteria_lower = (
        criteria.lower()
    )

    service_lower = (
        service.lower()
        .replace(
            " ",
            "_"
        )
    )

    # --------------------------------------------------------
    # Common product-name variations
    # --------------------------------------------------------

    aliases = {

        "apache":
            [
                "apache:http_server",
                "apache:httpd"
            ],

        "apache http server":
            [
                "apache:http_server",
                "apache:httpd"
            ],

        "openssh":
            [
                "openbsd:openssh"
            ],

        "nginx":
            [
                "nginx:nginx"
            ]
    }

    possible_names = aliases.get(
        service.lower(),
        [
            service_lower
        ]
    )

    for name in possible_names:

        if name in criteria_lower:

            return True

    return False


# ============================================================
# EXACT VERSION MATCH
# ============================================================

def cpe_matches_version(
    cpe,
    detected_version
):

    if not detected_version:
        return False

    criteria = cpe.get(
        "criteria",
        ""
    )

    # --------------------------------------------------------
    # Extract version from CPE
    # --------------------------------------------------------

    parts = criteria.split(":")

    cpe_version = None

    if len(parts) >= 6:

        cpe_version = parts[5]

    # --------------------------------------------------------
    # Wildcard version
    # --------------------------------------------------------

    if (
        cpe_version
        in
        (None, "*", "-")
    ):

        return version_in_range(

            detected_version,

            cpe.get(
                "versionStartIncluding"
            ),

            cpe.get(
                "versionStartExcluding"
            ),

            cpe.get(
                "versionEndIncluding"
            ),

            cpe.get(
                "versionEndExcluding"
            )
        )

    # --------------------------------------------------------
    # Exact version
    # --------------------------------------------------------

    comparison = compare_versions(
        detected_version,
        cpe_version
    )

    if comparison == 0:
        return True

    # --------------------------------------------------------
    # Range
    # --------------------------------------------------------

    return version_in_range(

        detected_version,

        cpe.get(
            "versionStartIncluding"
        ),

        cpe.get(
            "versionStartExcluding"
        ),

        cpe.get(
            "versionEndIncluding"
        ),

        cpe.get(
            "versionEndExcluding"
        )
    )


# ============================================================
# DETERMINE VULNERABILITY MATCH
# ============================================================

def determine_match(
    cve,
    service,
    version
):

    cpe_matches = get_cpe_matches(
        cve
    )

    potential_product_match = False

    for cpe in cpe_matches:

        criteria = cpe.get(
            "criteria",
            ""
        )

        if not cpe_matches_product(
            criteria,
            service
        ):
            continue

        potential_product_match = True

        if cpe_matches_version(
            cpe,
            version
        ):

            return {
                "status":
                    "CONFIRMED",

                "matched_cpe":
                    criteria
            }

    if potential_product_match:

        return {

            "status":
                "POTENTIAL",

            "matched_cpe":
                None
        }

    return {

        "status":
            "UNRELATED",

        "matched_cpe":
            None
    }


# ============================================================
# SEARCH NVD
# ============================================================

def search_nvd(
    keyword,
    results_per_page=20
):

    params = {

        "keywordSearch":
            keyword,

        "resultsPerPage":
            results_per_page
    }

    try:

        response = requests.get(

            NVD_API_URL,

            params=params,

            headers=HEADERS,

            timeout=20
        )

        response.raise_for_status()

        data = response.json()

        return data.get(
            "vulnerabilities",
            []
        )

    except requests.RequestException as error:

        print(
            f"NVD request failed: {error}"
        )

        return []


# ============================================================
# FORMAT CVE
# ============================================================

def format_cve(
    cve,
    service,
    version
):

    cve_id = cve.get(
        "id"
    )

    description = (
        get_description(
            cve
        )
    )

    cvss = (
        get_cvss(
            cve
        )
    )

    references = (
        get_references(
            cve
        )
    )

    match = (
        determine_match(
            cve,
            service,
            version
        )
    )

    return {

        "cve":
            cve_id,

        "service":
            service,

        "detected_version":
            version,

        "match_status":
            match["status"],

        "matched_cpe":
            match["matched_cpe"],

        "description":
            description,

        "cvss_version":
            cvss.get(
                "version"
            ),

        "cvss_score":
            cvss.get(
                "score"
            ),

        "severity":
            cvss.get(
                "severity"
            ),

        "references":
            references
    }


# ============================================================
# LOOKUP SOFTWARE
# ============================================================

def lookup_software(
    service,
    version
):

    if not service:

        return []

    if not version:

        return []

    keyword = (
        f"{service} {version}"
    )

    print()

    print(
        f"Searching NVD for: "
        f"{keyword}"
    )

    vulnerabilities = (
        search_nvd(
            keyword
        )
    )

    results = []

    seen_cves = set()

    for item in vulnerabilities:

        cve = item.get(
            "cve",
            {}
        )

        cve_id = cve.get(
            "id"
        )

        if not cve_id:
            continue

        if cve_id in seen_cves:
            continue

        seen_cves.add(
            cve_id
        )

        formatted = (
            format_cve(
                cve,
                service,
                version
            )
        )

        # ----------------------------------------------------
        # Only retain relevant matches
        # ----------------------------------------------------

        if formatted[
            "match_status"
        ] == "UNRELATED":

            continue

        results.append(
            formatted
        )

    return results


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print(
        "=" * 80
    )

    print(
        "NVD VERSION MATCHING TEST"
    )

    print(
        "=" * 80
    )

    results = lookup_software(
        "Apache HTTP Server",
        "2.4.49"
    )

    print()

    print(
        f"Relevant results: "
        f"{len(results)}"
    )

    for result in results[:10]:

        print()

        print(
            f"CVE: "
            f"{result['cve']}"
        )

        print(
            f"Product: "
            f"{result['service']}"
        )

        print(
            f"Detected version: "
            f"{result['detected_version']}"
        )

        print(
            f"Match status: "
            f"{result['match_status']}"
        )

        print(
            f"CVSS: "
            f"{result['cvss_score']}"
        )

        print(
            f"Severity: "
            f"{result['severity']}"
        )

        print(
            f"Description: "
            f"{result['description'][:250]}"
        )

        print(
            "-" * 80
        )