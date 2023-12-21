class scan4all < Formula
    desc "Official repository vuls Scan: 15000+PoCs; 23 kinds of application password crack; 7000+Web fingerprints; 146 protocols and 90000+ rules Port scanning; Fuzz, HW, awesome BugBounty( ͡° ͜ʖ ͡°)..."
    homepage "https://github.com/GhostTroops/scan4all"
    url "https://github.com/GhostTroops/scan4all/releases/download/2.9.0/scan4all_2.9.0_macOS_amd64.zip"
    sha256 "ccd874a283defad6a0deb11377cb9d6024cb5946b46f61f36008e0afe9db4950"
    version "V2.9.0"

    def install
      bin.install "scan4all"
    end
  end