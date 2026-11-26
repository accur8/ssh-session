# ssh-session, the package. The tests run in the build: they mint against a
# throwaway software CA and a stub account CA service, into a private ssh-agent.
{
  lib,
  python3,
  openssh,
  yubikey-manager,
  git,
}:
python3.pkgs.buildPythonApplication {
  pname = "ssh-session";
  version = "1.0.12";
  pyproject = true;
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./pyproject.toml
      ./ssh_session
      ./tests
    ];
  };
  build-system = [ python3.pkgs.setuptools ];
  dependencies = [ python3.pkgs.click ];
  nativeCheckInputs = [
    python3.pkgs.pytestCheckHook
    openssh
    git
  ];
  # nixpkgs' openssh ahead of the system's: the one with FIDO support, which
  # signing with a CA key on a YubiKey needs. ykman lists what is plugged in.
  makeWrapperArgs = [
    "--prefix"
    "PATH"
    ":"
    (lib.makeBinPath [
      openssh
      yubikey-manager
    ])
    # git for the managed checkouts (ssh-session tools), after the user's own: their git and its
    # config win wherever there is one
    "--suffix"
    "PATH"
    ":"
    (lib.makeBinPath [ git ])
  ];
  meta.mainProgram = "ssh-session";
}
