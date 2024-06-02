
cd /tmp

# install
sudo apt update
sudo apt install tmux

# install docker
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# -------------------------------------------------------------------------------------

# install trivy
sudo apt install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt update
sudo apt install trivy

# -------------------------------------------------------------------------------------

# grype install
wget https://github.com/anchore/grype/releases/download/v0.74.6/grype_0.74.6_linux_amd64.deb
sudo dpkg -i grype_0.74.6_linux_amd64.deb

# -------------------------------------------------------------------------------------

# snyk install
wget https://github.com/snyk/cli/releases/download/v1.1280.1/snyk-linux
mv snyk-linux /usr/local/bin/snyk
chmod +x /usr/local/bin/snyk

echo "[!!!] do not forget to login snyk"
echo "[!!!] do not forget to 'usermod -aG docker USER'"
