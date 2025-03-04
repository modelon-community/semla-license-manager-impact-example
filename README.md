# License Manager Impact Example

This project is an example of a [SEMLA](https://github.com/modelica/Encryption-and-Licensing) License Manager for Modelon Impact

## How to setup

- Run `setup.sh`. This will:
  - Git clone SEMLA to `../SEMLA` 
  - Generate keys for testing in `../openssl_keys`

The build system assumes that the directories are laid out like this:
```
openssl_keys/
SEMLA/
semla-license-manager-impact-example/    # (this directory)
```
- Set `MFL_JWT_LICENSE_FILE_FILENAME` in [./CMakePresets.json](./CMakePresets.json) to a name that is unique. `MFL_JWT_LICENSE_FILE_FILENAME` will be created in the user's home directory (`$HOME`).

## How to run

- Build and run the application by running: `./build.sh && ./run.sh`

This uses `ctest` (configured with a CMake Preset in [./CMakePresets.json](./CMakePresets.json)) to run the SEMLA test suite

## How to Update JWT Keys from wellknown
- Update JWT Keys from wellknown by running:
```
./update_jwt_keys_from_wellknown.sh
```

## How to release

- Run `./release.sh <next_version>` in a terminal standing in this directory (replacing `<next_version>` with a version number of the form `MAJOR.MINOR.PATCH`). This script will:
  - If the files are not already in a git repo, create a new local git repo on the fly.
  - Output a zip file `semla-license-manager-impact-example-<next_version>.zip` containing all files under version control in this repo, plus zip files for the dependencies (which are not under version control)
  - Create a new git tag `v<next_version>` on this repo.
  - If a remote repo  `origin` is configured: push the tag to the remote repo.

## How to develop

We recommend using VS Code with a devcontainer. There is a devcontainer set up in this repo, which enables an easy and reproducible setup.
The devcontainer mounts in the parent directory of this directory, so that both this directory, and the `../SEMLA` directory are available in the container.
Pre-requisites are that VS Code and Docker (and WSL if running on Windows) are installed.
For more information on how to use the devcontainer, search for "devcontainer" in:
- [SEMLA: Building instructions](https://github.com/modelica/Encryption-and-Licensing/blob/master/src)

## How to understand

Good starting points for understanding how this works is to look at the tests, in particular:
- [../SEMLA/src/tests/test_tool.c](../SEMLA/src/tests/test_tool.c)
  - (or the online version [SEMLA: test_tool.c](https://github.com/modelica/Encryption-and-Licensing/blob/master/src/tests/test_tool.c)) tests how a modelica tool uses the LVE (LVE = Library Vendor Executable -- the executable that is responsible for licensing and encryption). The LVE includes the License Manager.
- [./license_manager/tests/test_license_manager.cpp](./license_manager/tests/test_license_manager.cpp)
  - tests only the License Manager, without embedding it into an LVE.

