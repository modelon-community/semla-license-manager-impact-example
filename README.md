# License Manager Impact Example

This project is an example of a [SEMLA](https://github.com/modelica/Encryption-and-Licensing) License Manager for Modelon Impact

## How to setup for use online on https://impact.modelon.cloud
Login into your Modelon Impact cloud account.
Navigate to [Project explorer app](https://impact.modelon.cloud/user-redirect/impact/customizations/workspace_management/index.html?view=projects) and checkout 
this repository.

Use context menu to open VSCode in browser for this checkout. With default location the VSCode URL will be: 
https://impact.modelon.cloud/user-redirect/vscode/?folder=/home/jovyan/impact/local_projects/Semla-license-manager-impact-example 

Open terminal (Ctrl-Shift-C) and run the setup script: `./setup.sh`. The script will:
  - Git clone SEMLA repository to `../SEMLA` 
  - Download dependencies from a release in this repository
  - Generate keys for testing in `../openssl_keys`
  - Creates a Python virtual environment under build/venv and installs cmake into it.

Activate the build environment if you need to use cmake from command line with `source build/venv/activate`.

## How to setup locally
We recommend using VS Code with a devcontainer. There is a devcontainer set up in this repo, which enables an easy and reproducible setup.
The devcontainer mounts in the parent directory of this directory, so that both this directory, and the `../SEMLA` directory are available in the container.
Pre-requisites are that VS Code and Docker (and WSL if running on Windows) are installed.
For more information on how to use the devcontainer, search for "devcontainer" in:
- [SEMLA: Building instructions](https://github.com/modelica/Encryption-and-Licensing/blob/master/src)

- Run `setup.sh`. This will:
  - Git clone SEMLA to `../SEMLA` 
  - Download dependencies from a release in this repository
  - Generate keys for testing in `../openssl_keys`

The build system assumes that the directories are laid out like this:
```
openssl_keys/
SEMLA/
semla-license-manager-impact-example/    # (this directory)
```

## Create a license file
The example uses a text file called `license.mo` placed in the top level directory of the library. It is possible to 
configure a different license file name by changing `MFL_JWT_LICENSE_FILE_FILENAME` in [./CMakePresets.json](./CMakePresets.json).

The license file in this example is expected to have one line per username for the users to be licensed, e.g.,
```
model license
/*
name.lastname@company.com
*/
end license;
```

## How to build
Three build scripts are included:

- `build.sh` only builds a release version of the LVE and supporting tools. This is enough for using the example as is.
- `build-debug.sh` builds debug configuration as necessary for running the debugger (gdb) and all tests. 
   Building tests requires additional library (https://libcheck.github.io/check/ ) which is 
   automatically installed in dev container. Tests can be run with `./run.sh` which uses `ctest` configured with a 
   CMake Preset in [./CMakePresets.json](./CMakePresets.json)) to run the SEMLA test suite.

## How to Encrypt a Library
Locate the Modelon Impact project containing your library. On Modelon Impact cloud installation you can use VSCode in browser launched from the Project explorer app to do that.

The commands below can be run from the *build* directory created when running `build.sh` as described above. The examples assume running on https://impact.modelon.cloud. For a local setup you may need to adapt the path.

```
cd build
```

Start by encrypting the library using packagetool:
```
./packagetool -version 1.1 -language 3.2 -encrypt "true" -librarypath /home/jovyan/impact/local_projects/YouLibraryProject/YourLibrary/
```
This will encrypt and package the library into `YouLibrary.mol` file. Now copy the `.impact` directory to the build directory:
```
cp -a /home/jovyan/impact/local_projects/YouLibraryProject/.impact .
```
Adapt `build/.impact/project.json` file using a text editor to contain correct version information and skip any unneeded content sections, e.g.:
```
{
  "name": "YourLibrary",
  "format": "1.0.0",
  "version": "1.0.0-beta.1",
  "dependencies": [
    {
      "name": "Modelica",
      "versionSpecifier": "4.0.0"
    }
  ],
  "content": [
    {
      "relpath": "YourLibrary",
      "contentType": "MODELICA",
      "name": "YourLibrary",
      "defaultDisabled": false,
      "id": "b984a38211d34c8fab2901a242e963ef"
    }
  ],
  "executionOptions": []
}
```
[!IMPORTANT]  
The version information in the `project.json` file is used for tracking dependencies
of workspaces and compiled models. It needs to follow semantic version specification
(https://semver.org).
You MUST always update the project version when releasing the library to users. The project version
does not need to match Modelica library version exactly.

Add the updated .impact directory into the library package:
```
zip -ur YourLibrary.mol .impact
```

If running on https://impact.modelon.cloud and assuming you have added your
own username to the license file you may test the encryption and licensing by using Modelon Impact Python client, e.g., from a Jupyter notebook:
```
from modelon.impact.client import Client
client = Client()
workspace = client.create_workspace("TestNewLicensing")
new_library_file = "/home/jovyan/impact/local_projects/Semla-license-manager-impact-example/build/YourLibrary.mol"
library = workspace.import_dependency_from_zip(new_library_file).wait()

# compile a test model
model = w.get_model("YourLibrary.Example.SomeModel")
dynamic = w.get_custom_function('dynamic')
compiler_options = dynamic.get_compiler_options()
fmu = model.compile(compiler_options=compiler_options, compiler_log_level="debug").wait()
print(fmu.get_log())

# Cleaning up after testing:
workspace.delete()
library.delete()
```

If the compilation passes without issues your library is ready for distribution on Modelon Impact Cloud.

## How to Update JWT Keys from wellknown
JWT keys are downloaded as a part of `setup.sh` run and can be updated by running:
```
./update_jwt_keys_from_wellknown.sh
```

The URL to wellknown is set to the Modelon Cloud instance of Impact by default. The URL to wellknown is set in `JWKS_JSON_FILE_URL`  in [./wellknown_url.json](./wellknown_url.json]).

## How to understand

Good starting points for understanding how this works is to look at the tests, in particular:
- [../SEMLA/src/tests/test_tool.c](../SEMLA/src/tests/test_tool.c)
  - (or the online version [SEMLA: test_tool.c](https://github.com/modelica/Encryption-and-Licensing/blob/master/src/tests/test_tool.c)) tests how a modelica tool uses the LVE (LVE = Library Vendor Executable -- the executable that is responsible for licensing and encryption). The LVE includes the License Manager.
- [./license_manager/tests/test_license_manager.cpp](./license_manager/tests/test_license_manager.cpp)
  - tests only the License Manager, without embedding it into an LVE.

## How to release

- Run `./release.sh <next_version>` in a terminal standing in this directory (replacing `<next_version>` with a version number of the form `MAJOR.MINOR.PATCH`). This script will:
  - If the files are not already in a git repo, create a new local git repo on the fly.
  - Output a zip file `semla-license-manager-impact-example-<next_version>.zip` containing all files under version control in this repo, plus zip files for the dependencies (which are not under version control)
  - Create a new git tag `v<next_version>` on this repo.
  - If a remote repo  `origin` is configured: push the tag to the remote repo.

