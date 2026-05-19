class Temu < Formula
  desc "Automated cybersecurity scanner"
  homepage "https://github.com/sangkan-dev/temu"
  url "https://github.com/sangkan-dev/temu/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "REPLACE_WITH_RELEASE_TARBALL_SHA256"
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/cli")
  end

  test do
    system "#{bin}/temu", "--help"
  end
end
