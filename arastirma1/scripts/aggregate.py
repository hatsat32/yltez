import json, os, csv, logging

def get_imgname_from_filename(filename):
    if "__" in filename:
        _imgname = filename.removesuffix(".json").split("__")
        if len(_imgname) == 2:
            imgname = f"{_imgname[0]}:{_imgname[1]}"
        else:
            imgname = f"{_imgname[0]}/{_imgname[1]}:{_imgname[2]}"
    else:
        imgname = filename.removesuffix(".json")
    return imgname

def _trivy_vuln_score(vuln):
    _score = None
    try:
        _score = vuln["CVSS"]["nvd"]["V3Score"]
        return _score, "v3"
    except:
        pass

    try:
        _score = vuln["CVSS"]["nvd"]["V2Score"]
        return _score, "v2"
    except:
        pass

    try:
        _score = vuln["CVSS"]["redhat"]["V3Score"]
        return _score, "v3"
    except:
        pass

    try:
        _score = vuln["CVSS"]["ghsa"]["V3Score"]
        return _score, "v3"
    except:
        pass

    return None, None

def trivy_agg(csvwriter, _dir):
    files = os.listdir(f"./{_dir}/trivy/")

    for file in files:
        with open(f"./{_dir}/trivy/{file}") as f:
            json_content = json.loads(f.read())

        if "Results" not in json_content:
            continue

        imgname = get_imgname_from_filename(file)

        for result in json_content["Results"]:
            if "Vulnerabilities" not in result:
                continue

            for vuln in result["Vulnerabilities"]:
                if vuln["Severity"].lower() in ("negligible", "unknown"):
                    continue

                # =======================================================
                _score, _cvssversion = _trivy_vuln_score(vuln)
                if _score == None:
                    continue
                # =======================================================

                csvwriter.writerow({
                    "scanner": "trivy",
                    "imagetype": _dir,
                    "image": imgname,
                    "id": vuln["VulnerabilityID"],
                    "pkgname": vuln["PkgName"],
                    "pkgversion": vuln["InstalledVersion"],
                    # "status": vuln["Status"],
                    "severity": vuln["Severity"].lower(),
                    "score": _score,
                    "cvssversion": _cvssversion,
                })

def _grype_vuln_score(vuln):
    _score = None
    _cvssversion = None
    for sc in vuln["vulnerability"]["cvss"]:
        if sc["version"] in ("3.1", "3.0"):
            _score = sc["metrics"]["baseScore"]
            _cvssversion = "v3"
            return _score, _cvssversion
        elif sc["version"] == "2.0":
            _score = sc["metrics"]["baseScore"]
            _cvssversion = "v2"
            return _score, _cvssversion
        else:
            # print(json.dumps(vuln))
            pass

    for rv in vuln["relatedVulnerabilities"]:
        if rv["id"] != vuln["vulnerability"]["id"]:
            continue

        for sc in rv["cvss"]:
            if sc["version"] in ("3.1", "3.0"):
                _score = sc["metrics"]["baseScore"]
                _cvssversion = "v3"
                return _score, _cvssversion
            elif sc["version"] == "2.0":
                _score = sc["metrics"]["baseScore"]
                _cvssversion = "v2"
                return _score, _cvssversion
            else:
                # print(json.dumps(vuln))
                pass

    # try to match amazon vulns with cve. currently does not work.
    # if _score == None and vuln["vulnerability"]["id"].startswith("ALAS"):
    #     print(json.dumps(vuln))
    #     exit()
    return _score, _cvssversion


def grype_agg(csvwriter, dirname):
    def extract_cve(vuln: dict) -> float|None:
        pass

    files = os.listdir(f"./{dirname}/grype/")

    for file in files:
        with open(f"./{dirname}/grype/{file}") as f:
            json_content = json.loads(f.read())

        if "matches" not in json_content:
            continue

        imgname = get_imgname_from_filename(file)

        for vuln in json_content["matches"]:
            # print(vuln["matchDetails"][0]["searchedBy"])

            _package=None
            try:
                _package = vuln["matchDetails"][0]["searchedBy"]["package"]
            except:
                _package = vuln["matchDetails"][0]["searchedBy"]["Package"]

            if vuln["vulnerability"]["severity"].lower() in ("negligible", "unknown"):
                continue

            # ==================================================================
            _score, _cvssversion = _grype_vuln_score(vuln)
            if _score == None:
                # print(json.dumps(vuln))
                continue
            # ==================================================================
            csvwriter.writerow({
                "scanner": "grype",
                "imagetype": dirname,
                "image": imgname,
                "id": vuln["vulnerability"]["id"],
                "pkgname": _package["name"],
                "pkgversion": _package["version"],
                "severity": vuln["vulnerability"]["severity"].lower(),
                "score": _score,
                "cvssversion": _cvssversion,
            })


def snyk_agg(csvwriter, dirname):
    files = os.listdir(f"./{dirname}/snyk/")

    for file in files:
        with open(f"./{dirname}/snyk/{file}") as f:
            json_content = json.loads(f.read())

        if "vulnerabilities" not in json_content:
            continue
        
        imgname = get_imgname_from_filename(file)

        for vuln in json_content["vulnerabilities"]:
            _id = vuln["id"]

            if vuln["severity"].lower() in ("negligible", "unknown"):
                continue

            try:
                _id = vuln["identifiers"]["CVE"][0]
            except:
                # print(json.dumps(vuln["identifiers"]["CVE"]))
                pass

            _cvssversion = "v3" if "CVSSv3" in vuln else None
            csvwriter.writerow({
                "scanner": "snyk",
                "imagetype": dirname,
                "image": imgname,
                "id": _id,
                "pkgname": vuln["packageName"],
                "pkgversion": vuln["version"],
                "severity": vuln["severity"].lower(),
                "score": vuln["cvssScore"],
                "cvssversion": _cvssversion,
            })


def main():
    dirs = ["scan-library", "scan-opensource", "scan-verified"]
    with open ("./results/results.csv", "w") as csvfile:
        csvwriter = csv.DictWriter(
            csvfile,
            fieldnames=[
                "scanner", "imagetype", "image", 'id', 'pkgname',
                "pkgversion", "severity", "score", "cvssversion"
                ]
        )
        csvwriter.writeheader()

        for dirname in dirs:
            trivy_agg(csvwriter, dirname)
            grype_agg(csvwriter, dirname)
            snyk_agg(csvwriter, dirname)

if __name__ == "__main__":
    main()
