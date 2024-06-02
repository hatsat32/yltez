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


def get_img_name_and_tag(image: str) -> tuple[str, str]:
    imgname, imgtag = image.split(":")
    return (imgname, imgtag)


def _trivy_vuln_score(vuln):
    _score = None
    try:
        _score = vuln["CVSS"]["nvd"]["V3Score"]
        return _score
    except:
        pass

    try:
        _score = vuln["CVSS"]["nvd"]["V2Score"]
        return _score
    except:
        pass

    try:
        _score = vuln["CVSS"]["redhat"]["V3Score"]
        return _score
    except:
        pass

    try:
        _score = vuln["CVSS"]["ghsa"]["V3Score"]
        return _score
    except:
        pass

    return None

def trivy_agg(csvwriter, period: str, _dir):
    files = os.listdir(f"./{period}/{_dir}/trivy/")

    for file in files:
        with open(f"./{period}/{_dir}/trivy/{file}") as f:
            json_content = json.loads(f.read())

        if "Results" not in json_content:
            continue

        imagename = get_imgname_from_filename(file)
        imgname, imgtag = get_img_name_and_tag(imagename)

        for result in json_content["Results"]:
            if "Vulnerabilities" not in result:
                continue

            for vuln in result["Vulnerabilities"]:
                if vuln["Severity"].lower() in ("negligible", "unknown"):
                    continue

                # =======================================================
                _score = _trivy_vuln_score(vuln)
                if _score == None:
                    continue
                # =======================================================

                if vuln["Status"] == "fixed":
                    _fixstatus = "fixed"
                elif vuln["Status"] in ("end_of_life", "will_not_fix"):
                    _fixstatus = "wont-fix"
                else:
                    _fixstatus = "not-fixed"
                    

                csvwriter.writerow({
                    "scanner": "trivy",
                    "period": period,
                    "imagetype": _dir,
                    "image": imagename,
                    "imgname": imgname,
                    "imgtag": imgtag,
                    "id": vuln["VulnerabilityID"],
                    "pkgname": vuln["PkgName"],
                    "pkgversion": vuln["InstalledVersion"],
                    "severity": vuln["Severity"].lower(),
                    "score": _score,
                    "fixstatus": _fixstatus,
                })

def _grype_vuln_score(vuln):
    _score = None
    for sc in vuln["vulnerability"]["cvss"]:
        if sc["version"] in ("3.1", "3.0"):
            _score = sc["metrics"]["baseScore"]
            return _score
        elif sc["version"] == "2.0":
            _score = sc["metrics"]["baseScore"]
            return _score
        else:
            # print(json.dumps(vuln))
            pass

    for rv in vuln["relatedVulnerabilities"]:
        if rv["id"] != vuln["vulnerability"]["id"]:
            continue

        for sc in rv["cvss"]:
            if sc["version"] in ("3.1", "3.0"):
                _score = sc["metrics"]["baseScore"]
                return _score
            elif sc["version"] == "2.0":
                _score = sc["metrics"]["baseScore"]
                return _score
            else:
                # print(json.dumps(vuln))
                pass

    # try to match amazon vulns with cve. currently does not work.
    # if _score == None and vuln["vulnerability"]["id"].startswith("ALAS"):
    #     print(json.dumps(vuln))
    #     exit()
    return _score


def grype_agg(csvwriter, period: str, dirname):
    def extract_cve(vuln: dict) -> float|None:
        pass

    files = os.listdir(f"./{period}/{dirname}/grype/")

    for file in files:
        with open(f"./{period}/{dirname}/grype/{file}") as f:
            json_content = json.loads(f.read())

        if "matches" not in json_content:
            continue

        imagename = get_imgname_from_filename(file)
        imgname, imgtag = get_img_name_and_tag(imagename)

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
            _score = _grype_vuln_score(vuln)
            if _score == None:
                # print(json.dumps(vuln))
                continue
            # ==================================================================vuln["fix"]["state"]

            # try:
            #     vuln["fix"]["state"]
            # except:
            #     print(period, dirname, file)
            #     print(json.dumps(vuln))
            #     # print(vuln["fix"]["state"])
            #     exit()

            _fixstatus = vuln["vulnerability"]["fix"]["state"]
            if _fixstatus == "unknown":
                _fixstatus = "not-fixed"

            csvwriter.writerow({
                "scanner": "grype",
                "period": period,
                "imagetype": dirname,
                "image": imagename,
                "imgname": imgname,
                "imgtag": imgtag,
                "id": vuln["vulnerability"]["id"],
                "pkgname": _package["name"],
                "pkgversion": _package["version"],
                "severity": vuln["vulnerability"]["severity"].lower(),
                "score": _score,
                "fixstatus": _fixstatus,
            })


def snyk_agg(csvwriter, period: str, dirname):
    files = os.listdir(f"./{period}/{dirname}/snyk/")

    for file in files:
        with open(f"./{period}/{dirname}/snyk/{file}") as f:
            try:
                json_content = json.loads(f.read())
            except Exception as e:
                print(">err>", dirname, f"./{dirname}/snyk/{file}")
        if "vulnerabilities" not in json_content:
            continue
        
        imagename = get_imgname_from_filename(file)
        imgname, imgtag = get_img_name_and_tag(imagename)

        for vuln in json_content["vulnerabilities"]:
            _id = vuln["id"]

            if vuln["severity"].lower() in ("negligible", "unknown"):
                continue

            try:
                _id = vuln["identifiers"]["CVE"][0]
            except:
                # print(json.dumps(vuln["identifiers"]["CVE"]))
                pass

            _fixstatus = "not-fixed" if len(vuln["fixedIn"]) == 0 else "fixed"
            csvwriter.writerow({
                "scanner": "snyk",
                "period": period,
                "imagetype": dirname,
                "image": imagename,
                "imgname": imgname,
                "imgtag": imgtag,
                "id": _id,
                "pkgname": vuln["packageName"],
                "pkgversion": vuln["version"],
                "severity": vuln["severity"].lower(),
                "score": vuln["cvssScore"],
                "fixstatus": _fixstatus,
            })


def main():
    dirs = [
        "2023_01/library", "2023_01/opensource", "2023_01/verified",
        "2023_07/library", "2023_07/opensource", "2023_07/verified",
        "2024_01/library", "2024_01/opensource", "2024_01/verified",
    ]
    csvfieldnames =[
        "scanner", "period", "imagetype", "image", "imgname", "imgtag", 'id',
        'pkgname', "pkgversion", "severity", "score", "fixstatus"
    ]
    periods = ["2023_01", "2023_07", "2024_01"]
    imgtypes = ["library", "opensource", "verified"]
    with open ("results.csv", "w") as csvfile:
        csvwriter = csv.DictWriter(csvfile, fieldnames=csvfieldnames)
        csvwriter.writeheader()

        for period in periods:
            for imgtype in imgtypes:
                trivy_agg(csvwriter, period, imgtype)
                grype_agg(csvwriter, period, imgtype)
                snyk_agg(csvwriter, period, imgtype)

if __name__ == "__main__":
    main()
