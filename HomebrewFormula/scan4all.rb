class Rage < Formula
    desc "Official repository vuls Scan: 15000+PoCs; 23 kinds of application password crack; 7000+Web fingerprints; 146 protocols and 90000+ rules Port scanning; Fuzz, HW, awesome BugBounty( ͡° ͜ʖ ͡°)..."
    homepage "https://scan4all.51pwn.com"
    szUrl "https://github.com/hktalent/scan4all/releases/download/2.8.1/scan4all_2.8.1_macOS_amd64.zip"
    sha256 "2af8d9f67bae7c03ef20d064b2f23e7bef4c95f0cf7e1da33cbd42fcceabeb39"
    version "2.8.1"

    depends_on "rust" => :build

    def install
        system "cargo", "install", *std_cargo_args(path: './scan4all_2.8.1_macOS_amd64')
    end

    test do
    end
end