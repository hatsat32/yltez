import requests

def login():
    creds = {"username": "<******>", "password": "<******>"}
    res = requests.post("https://hub.docker.com/v2/users/login", json=creds)
    token = res.json()["token"]
    return token

def check_tag(token: str, ns, repo):
    namespace = ns
    repository = repo
    tag = "latest"
    res = requests.head(
        url=f"https://hub.docker.com/v2/namespaces/{namespace}/repositories/{repository}/tags/{tag}",
    )
    return res.status_code == 200

def read_repo_tags(token: str, ns, repo):
    namespace = ns
    repository = repo
    res = requests.get(
        url=f"https://hub.docker.com/v2/namespaces/{namespace}/repositories/{repository}/tags"
    )
    return res.json()

def main():
    token = login()
    # with open("open_source.all.txt") as file:
    with open("verified_publisher.all.txt") as file:
        for line in file:
            ns, repo = line.strip().split("/")
            # print(ns, repo)
            checked = check_tag(token, ns, repo)
            
            if checked == True:
                # tags = read_repo_tags(token, ns, repo)
                print(f"[+] {ns}/{repo}:latest")
            else:
                print(f"[!] {ns}/{repo}:")

if __name__ == "__main__":
    main()
